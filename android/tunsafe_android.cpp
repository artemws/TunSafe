// tunsafe_android.cpp
// Implements TunSafe* C functions declared in tunsafe_jni.cpp.
// Compiled with tunsafe_core.cpp (Android-only source list) via CMakeLists.txt.

#include "build_config.h"
#include "tunsafe_types.h"
#include "wireguard.h"
#include "wireguard_config.h"
#include "tunsafe_threading.h"
#include "util.h"
#include "crypto/curve25519/curve25519-donna.h"

#include <android/log.h>
#include <pthread.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>

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

// Public accessors for the WireGuard engine (called from network_android.cpp)
int AndroidConfigureTun(const char* config) {
    return g_configureTun ? g_configureTun(config) : -1;
}
void AndroidOnConnected()                           { if (g_onConnected)       g_onConnected(); }
void AndroidOnConnectionRetry(int delay)            { if (g_onConnectionRetry) g_onConnectionRetry(delay); }
void AndroidOnPingReply(const char* ip, int ms)     { if (g_onPingReply)       g_onPingReply(ip, ms); }
void AndroidOnRequestToken(int type)                { if (g_onRequestToken)    g_onRequestToken(type); }
void AndroidProtectFd(int fd)                       { if (g_protectFd)         g_protectFd(fd); }
bool AndroidReleaseFd(int fd)                       { return g_releaseFd ? g_releaseFd(fd) : false; }

// ── Log ring buffer ───────────────────────────────────────────────────────────

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::string     g_log_buf;
static const size_t    LOG_MAX = 64 * 1024;

static void AppendLog(const char* line) {
    pthread_mutex_lock(&g_log_mutex);
    g_log_buf += line;
    g_log_buf += '\n';
    if (g_log_buf.size() > LOG_MAX)
        g_log_buf = g_log_buf.substr(g_log_buf.size() - LOG_MAX / 2);
    pthread_mutex_unlock(&g_log_mutex);
    LOGI("%s", line);
}

// Hook called from util.cpp
extern "C" void LogLine(const char* line) { AppendLog(line); }

extern "C" char* TunSafeGetLog() {
    pthread_mutex_lock(&g_log_mutex);
    char* r = strdup(g_log_buf.c_str());
    pthread_mutex_unlock(&g_log_mutex);
    return r;
}

// ── Stats ─────────────────────────────────────────────────────────────────────

static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t g_rx = 0, g_tx = 0, g_conn_time = 0;

extern "C" void TunSafeGetStats(int64_t* rx, int64_t* tx, int64_t* conn_time) {
    pthread_mutex_lock(&g_stats_mutex);
    *rx = g_rx; *tx = g_tx; *conn_time = g_conn_time;
    pthread_mutex_unlock(&g_stats_mutex);
}

// Called from the network backend to update stats
void AndroidUpdateStats(int64_t rx, int64_t tx, int64_t conn_time_sec) {
    pthread_mutex_lock(&g_stats_mutex);
    g_rx = rx; g_tx = tx; g_conn_time = conn_time_sec;
    pthread_mutex_unlock(&g_stats_mutex);
}

// ── Engine thread ─────────────────────────────────────────────────────────────
// network_android.cpp provides WireGuardNetworkStart which runs the event loop.
// Forward declarations — implemented in network_android.cpp

void WireGuardNetworkStart(const char* config, bool kill_switch);
void WireGuardNetworkStop();
bool WireGuardNetworkPing(const char* server);
bool WireGuardNetworkSetPingServer(const char* server);
void WireGuardNetworkRetryNow();
void WireGuardNetworkSubmitToken(const char* token);
void WireGuardNetworkCloseFd(int fd);
void WireGuardNetworkPurgeFd(int fd);
void WireGuardNetworkPostExit(bool graceful);

struct EngineParams { std::string config; bool kill_switch; };
static pthread_t g_engine_thread = 0;
static bool      g_engine_running = false;

static void* EngineThread(void* arg) {
    EngineParams* p = (EngineParams*)arg;
    AppendLog("TunSafe engine thread starting");
    WireGuardNetworkStart(p->config.c_str(), p->kill_switch);
    AppendLog("TunSafe engine thread exiting");
    g_engine_running = false;
    delete p;
    return nullptr;
}

extern "C" int TunSafeStart(const char* config, bool kill_switch) {
    if (g_engine_running) {
        AppendLog("Stopping previous engine");
        WireGuardNetworkStop();
        if (g_engine_thread) { pthread_join(g_engine_thread, nullptr); g_engine_thread = 0; }
    }
    auto* p = new EngineParams{std::string(config), kill_switch};
    g_engine_running = true;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    int ret = pthread_create(&g_engine_thread, &attr, EngineThread, p);
    pthread_attr_destroy(&attr);
    if (ret != 0) { g_engine_running = false; delete p; return -1; }
    return 0;
}

extern "C" void TunSafeStop()               { WireGuardNetworkStop(); }
extern "C" void TunSafeRetryNow()           { WireGuardNetworkRetryNow(); }
extern "C" void TunSafeCloseFd(int fd)      { WireGuardNetworkCloseFd(fd); }
extern "C" void TunSafePurgeFd(int fd)      { WireGuardNetworkPurgeFd(fd); }
extern "C" void TunSafePostExit(bool g)     { WireGuardNetworkPostExit(g); }
extern "C" bool TunSafePing(const char* s)  { return WireGuardNetworkPing(s); }
extern "C" bool TunSafeSetPingServer(const char* s) { return WireGuardNetworkSetPingServer(s); }
extern "C" void TunSafeSubmitToken(const char* t)   { WireGuardNetworkSubmitToken(t); }

// ── Key utilities ─────────────────────────────────────────────────────────────

static const char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode(const uint8_t* in, int len, char* out) {
    int i = 0, j = 0;
    while (len > 0) {
        uint32_t b = (uint32_t)in[i++] << 16 |
                     (len > 1 ? (uint32_t)in[i++] : 0u) << 8 |
                     (len > 2 ? (uint32_t)in[i++] : 0u);
        out[j++] = kB64[(b >> 18) & 0x3f];
        out[j++] = kB64[(b >> 12) & 0x3f];
        out[j++] = len > 1 ? kB64[(b >>  6) & 0x3f] : '=';
        out[j++] = len > 2 ? kB64[(b >>  0) & 0x3f] : '=';
        len -= 3;
    }
    out[j] = '\0';
}

static int b64_decode(const char* in, uint8_t* out, int max) {
    static const int8_t T[256] = {
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
    while (*in && n + 3 <= max) {
        int a = T[(uint8_t)in[0]], b = T[(uint8_t)in[1]];
        int c = in[2] == '=' ? 0 : T[(uint8_t)in[2]];
        int d = in[3] == '=' ? 0 : T[(uint8_t)in[3]];
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
    if (b64_decode(privkey_b64, priv, 32) == 32) {
        static const uint8_t basepoint[32] = {9};
        // curve25519_donna_ref is a regular C++ function — call without extern "C"
        curve25519_donna_ref(pub, priv, basepoint);
        b64_encode(pub, 32, out_buf);
    } else {
        out_buf[0] = '\0';
    }
}

extern "C" void TunSafeGeneratePrivateKey(char* out_buf) {
    uint8_t key[32] = {};
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { (void)read(fd, key, 32); close(fd); }
    key[0]  &= 248;
    key[31] &= 127;
    key[31] |= 64;
    b64_encode(key, 32, out_buf);
}

extern "C" void TunSafeGetExternalIp(const char* /*server*/, char* out_buf, int out_len) {
    if (out_len > 0) out_buf[0] = '\0';
}
