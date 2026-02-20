// tunsafe_android.cpp
// Implements the TunSafe* C functions declared in tunsafe_jni.cpp.
// Wraps the tunsafe_amalgam.cpp core for Android.
//
// Build note: compiled together with tunsafe_amalgam.cpp via CMakeLists.txt.

#include "build_config.h"
#include "tunsafe_types.h"
#include "wireguard.h"
#include "wireguard_config.h"
#include "wireguard_proto.h"
#include "tunsafe_threading.h"
#include "tunsafe_cpu.h"
#include "util.h"
#include "crypto/curve25519/curve25519-donna.h"

#include <android/log.h>
#include <pthread.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "TunSafeCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ── Callback function pointers (set by JNI layer) ────────────────────────────

typedef int  (*ConfigureTunFn)(const char*);
typedef void (*OnConnectedFn)();
typedef void (*OnConnectionRetryFn)(int);
typedef void (*OnPingReplyFn)(const char*, int);
typedef void (*OnRequestTokenFn)(int);
typedef void (*ProtectFdFn)(int);
typedef bool (*ReleaseFdFn)(int);

static ConfigureTunFn      g_configureTun      = nullptr;
static OnConnectedFn       g_onConnected       = nullptr;
static OnConnectionRetryFn g_onConnectionRetry = nullptr;
static OnPingReplyFn       g_onPingReply       = nullptr;
static OnRequestTokenFn    g_onRequestToken    = nullptr;
static ProtectFdFn         g_protectFd         = nullptr;
static ReleaseFdFn         g_releaseFd         = nullptr;

extern "C" void TunSafeSetCallbacks(
        ConfigureTunFn      configureTun,
        OnConnectedFn       onConnected,
        OnConnectionRetryFn onConnectionRetry,
        OnPingReplyFn       onPingReply,
        OnRequestTokenFn    onRequestToken,
        ProtectFdFn         protectFd,
        ReleaseFdFn         releaseFd) {
    g_configureTun      = configureTun;
    g_onConnected       = onConnected;
    g_onConnectionRetry = onConnectionRetry;
    g_onPingReply       = onPingReply;
    g_onRequestToken    = onRequestToken;
    g_protectFd         = protectFd;
    g_releaseFd         = releaseFd;
}

// ── Log ring buffer ───────────────────────────────────────────────────────────

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::string     g_log_buf;
static const size_t    LOG_MAX = 64 * 1024;

static void AppendLog(const char* line) {
    pthread_mutex_lock(&g_log_mutex);
    g_log_buf += line;
    g_log_buf += '\n';
    if (g_log_buf.size() > LOG_MAX) {
        // Keep last half
        g_log_buf = g_log_buf.substr(g_log_buf.size() - LOG_MAX / 2);
    }
    pthread_mutex_unlock(&g_log_mutex);
    LOGI("%s", line);
}

// Hook for TunSafe core logging (implement the weak symbol used by util.cpp)
extern "C" void LogLine(const char* line) {
    AppendLog(line);
}

extern "C" char* TunSafeGetLog() {
    pthread_mutex_lock(&g_log_mutex);
    char* result = strdup(g_log_buf.c_str());
    pthread_mutex_unlock(&g_log_mutex);
    return result;
}

// ── Stats ─────────────────────────────────────────────────────────────────────

static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t g_rx_bytes = 0, g_tx_bytes = 0, g_conn_time = 0;

extern "C" void TunSafeGetStats(int64_t* rx, int64_t* tx, int64_t* conn_time) {
    pthread_mutex_lock(&g_stats_mutex);
    *rx        = g_rx_bytes;
    *tx        = g_tx_bytes;
    *conn_time = g_conn_time;
    pthread_mutex_unlock(&g_stats_mutex);
}

// Called by the network backend to update stats
void UpdateStats(int64_t rx, int64_t tx, int64_t conn_time_sec) {
    pthread_mutex_lock(&g_stats_mutex);
    g_rx_bytes  = rx;
    g_tx_bytes  = tx;
    g_conn_time = conn_time_sec;
    pthread_mutex_unlock(&g_stats_mutex);
}

// ── Engine thread ─────────────────────────────────────────────────────────────

struct EngineParams {
    std::string config;
    bool        kill_switch;
};

static pthread_t g_engine_thread = 0;
static bool      g_engine_running = false;

// The WireGuard/TunSafe engine entry point.
// network_bsd.cpp (Android flavour) calls g_configureTun, g_protectFd etc.
// We need to forward those calls to the Java layer via our callback pointers.

// These are weak-linked hooks called from the BSD network backend.
// Override them here to route through our Java callbacks.

extern "C" int  PlatformConfigureTun(const char* config) {
    if (g_configureTun) return g_configureTun(config);
    return -1;
}

extern "C" void PlatformOnConnected() {
    if (g_onConnected) g_onConnected();
}

extern "C" void PlatformOnConnectionRetry(int delay) {
    if (g_onConnectionRetry) g_onConnectionRetry(delay);
}

extern "C" void PlatformOnPingReply(const char* ip, int ms) {
    if (g_onPingReply) g_onPingReply(ip, ms);
}

extern "C" void PlatformOnRequestToken(int type) {
    if (g_onRequestToken) g_onRequestToken(type);
}

extern "C" void PlatformProtectFd(int fd) {
    if (g_protectFd) g_protectFd(fd);
}

extern "C" bool PlatformReleaseFd(int fd) {
    if (g_releaseFd) return g_releaseFd(fd);
    return false;
}

static void* EngineThread(void* arg) {
    EngineParams* p = (EngineParams*)arg;
    AppendLog("TunSafe engine thread starting");

    // The BSD network backend runs its own event loop.
    // Include tunsafe_bsd.cpp's entry point:
    extern int TunSafeRunBSD(const char* config, bool kill_switch);
    int ret = TunSafeRunBSD(p->config.c_str(), p->kill_switch);

    AppendLog("TunSafe engine thread exiting");
    g_engine_running = false;
    delete p;
    return (void*)(intptr_t)ret;
}

extern "C" int TunSafeStart(const char* config, bool kill_switch) {
    if (g_engine_running) {
        AppendLog("TunSafeStart: stopping previous engine");
        TunSafeStop();
        if (g_engine_thread) {
            pthread_join(g_engine_thread, nullptr);
            g_engine_thread = 0;
        }
    }

    auto* p = new EngineParams{std::string(config), kill_switch};
    g_engine_running = true;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int ret = pthread_create(&g_engine_thread, &attr, EngineThread, p);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        LOGE("TunSafeStart: pthread_create failed: %s", strerror(ret));
        g_engine_running = false;
        delete p;
        return -1;
    }

    AppendLog("TunSafeStart: engine launched");
    return 0;
}

extern "C" void TunSafeStop() {
    extern void TunSafeStopBSD();
    TunSafeStopBSD();
}

extern "C" void TunSafeRetryNow() {
    extern void TunSafeRetryNowBSD();
    TunSafeRetryNowBSD();
}

extern "C" void TunSafeCloseFd(int fd) {
    extern void TunSafeCloseFdBSD(int);
    TunSafeCloseFdBSD(fd);
}

extern "C" void TunSafePurgeFd(int fd) {
    extern void TunSafePurgeFdBSD(int);
    TunSafePurgeFdBSD(fd);
}

extern "C" void TunSafePostExit(bool graceful) {
    extern void TunSafePostExitBSD(bool);
    TunSafePostExitBSD(graceful);
}

extern "C" bool TunSafePing(const char* server) {
    extern bool TunSafePingBSD(const char*);
    return TunSafePingBSD(server);
}

extern "C" bool TunSafeSetPingServer(const char* server) {
    extern bool TunSafeSetPingServerBSD(const char*);
    return TunSafeSetPingServerBSD(server);
}

extern "C" void TunSafeSubmitToken(const char* token) {
    extern void TunSafeSubmitTokenBSD(const char*);
    TunSafeSubmitTokenBSD(token);
}

// ── Key utilities ─────────────────────────────────────────────────────────────

// Base64 encoding table
static const char kBase64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const uint8_t* in, int in_len, char* out) {
    int i = 0, j = 0;
    while (in_len > 0) {
        uint32_t b = (in_len > 0 ? in[i++] : 0) << 16 |
                     (in_len > 1 ? in[i++] : 0) << 8  |
                     (in_len > 2 ? in[i++] : 0);
        out[j++] = kBase64[(b >> 18) & 0x3f];
        out[j++] = kBase64[(b >> 12) & 0x3f];
        out[j++] = in_len > 1 ? kBase64[(b >>  6) & 0x3f] : '=';
        out[j++] = in_len > 2 ? kBase64[(b >>  0) & 0x3f] : '=';
        in_len -= 3;
    }
    out[j] = '\0';
}

static int base64_decode(const char* in, uint8_t* out, int out_max) {
    static const int8_t kDec[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    int n = 0;
    while (*in && n + 3 <= out_max) {
        int a = kDec[(uint8_t)in[0]], b = kDec[(uint8_t)in[1]];
        int c = in[2] == '=' ? 0 : kDec[(uint8_t)in[2]];
        int d = in[3] == '=' ? 0 : kDec[(uint8_t)in[3]];
        if (a < 0 || b < 0) break;
        out[n++] = (a << 2) | (b >> 4);
        if (in[2] != '=') out[n++] = (b << 4) | (c >> 2);
        if (in[3] != '=') out[n++] = (c << 6) | d;
        in += 4;
    }
    return n;
}

extern "C" void TunSafeGetPublicKey(const char* privkey_b64, char* out_buf) {
    uint8_t priv[32] = {}, pub[32] = {};
    if (base64_decode(privkey_b64, priv, 32) == 32) {
        // curve25519 scalar multiplication: pub = priv * G
        // Using curve25519-donna from TunSafe's crypto/
        extern void curve25519_donna(uint8_t*, const uint8_t*, const uint8_t*);
        static const uint8_t basepoint[32] = {9};
        curve25519_donna(pub, priv, basepoint);
        base64_encode(pub, 32, out_buf);
    } else {
        out_buf[0] = '\0';
    }
}

extern "C" void TunSafeGeneratePrivateKey(char* out_buf) {
    uint8_t key[32];
    // Read from /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, key, 32);
        close(fd);
    } else {
        // Fallback: not cryptographically safe, but shouldn't happen on Android
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(rand() >> 8);
    }
    // Apply WireGuard clamping
    key[0]  &= 248;
    key[31] &= 127;
    key[31] |= 64;
    base64_encode(key, 32, out_buf);
}

extern "C" void TunSafeGetExternalIp(const char* /*server*/, char* out_buf, int out_len) {
    // Minimal implementation: try to get the IP from the tunnel interface
    // The real implementation would query a STUN/external service.
    // For now return empty and let Java fall back to its own mechanism.
    if (out_len > 0) out_buf[0] = '\0';
}
