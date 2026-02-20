// tunsafe_jni.cpp
// JNI bridge between Android Java (com.tunsafe.service.TunsafeVpnService)
// and the TunSafe C++ core (tunsafe_amalgam.cpp).
//
// All function signatures are extracted from the original APK's DEX bytecode.
// Java class: com.tunsafe.service.TunsafeVpnService
// Java class: com.tunsafe.app.NativeCallbacks

#include <jni.h>
#include <android/log.h>
#include <string>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

// ── TunSafe core includes ─────────────────────────────────────────────────────
#include "build_config.h"
#include "tunsafe_types.h"
#include "wireguard.h"
#include "wireguard_config.h"
#include "tunsafe_threading.h"
#include "util.h"

#define LOG_TAG "TunSafeJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ── Global state ──────────────────────────────────────────────────────────────

static JavaVM* g_jvm = nullptr;

// Cached references to the Java NativeCallbacks object and its methods.
// Set once during nativeInitialize(), used from C++ callbacks.
struct JavaCallbacks {
    jweak     obj;           // weak ref to NativeCallbacks instance

    jmethodID configureTun;  // (Ljava/lang/String;)I
    jmethodID onConnected;   // ()V
    jmethodID onConnectionRetry; // (I)V
    jmethodID onPingReply;   // (Ljava/lang/String;I)V
    jmethodID onRequestToken;// (I)V
    jmethodID protectFd;     // (I)V
    jmethodID releaseFd;     // (I)Z
};

static JavaCallbacks g_cb = {};

// Forward-declared C++ callbacks (implemented below)
static int  cb_configureTun(const char* config);
static void cb_onConnected();
static void cb_onConnectionRetry(int delay_sec);
static void cb_onPingReply(const char* ip, int latency_ms);
static void cb_onRequestToken(int type);
static void cb_protectFd(int fd);
static bool cb_releaseFd(int fd);

// ── TunSafe backend glue ──────────────────────────────────────────────────────
// The actual WireGuard/TunSafe engine. Implemented in tunsafe_bsd.cpp /
// network_bsd.cpp compiled for Android. We declare a minimal interface here.

// Defined in network_bsd.cpp (Android build) or a thin wrapper:
extern "C" {
    // Start TunSafe with given WireGuard config string.
    // Returns 0 on success.
    int  TunSafeStart(const char* config, bool kill_switch);

    // Stop the running tunnel.
    void TunSafeStop();

    // Get current log buffer as newline-separated string (caller frees).
    char* TunSafeGetLog();

    // Get stats: rx_bytes, tx_bytes, connection_time_sec
    void TunSafeGetStats(int64_t* rx, int64_t* tx, int64_t* conn_time);

    // Get the public key for the given private key (base64 in, base64 out).
    // out_buf must be >= 48 bytes.
    void TunSafeGetPublicKey(const char* privkey_b64, char* out_buf);

    // Generate a fresh private key into out_buf (>= 48 bytes).
    void TunSafeGeneratePrivateKey(char* out_buf);

    // Get external IP (best-effort, may return empty string).
    void TunSafeGetExternalIp(const char* server_hint, char* out_buf, int out_len);

    // Ping a server. Returns true if ping was sent.
    bool TunSafePing(const char* server);

    // Set the server to use for latency pings.
    bool TunSafeSetPingServer(const char* server);

    // Submit a TOTP/auth token.
    void TunSafeSubmitToken(const char* token);

    // Retry connection immediately.
    void TunSafeRetryNow();

    // Notify the engine that the tun fd was closed externally.
    void TunSafeCloseFd(int fd);

    // Notify the engine that the tun fd was purged.
    void TunSafePurgeFd(int fd);

    // Signal exit to engine threads.
    void TunSafePostExit(bool graceful);

    // Register C-level callbacks.
    typedef int  (*ConfigureTunFn)(const char*);
    typedef void (*OnConnectedFn)();
    typedef void (*OnConnectionRetryFn)(int);
    typedef void (*OnPingReplyFn)(const char*, int);
    typedef void (*OnRequestTokenFn)(int);
    typedef void (*ProtectFdFn)(int);
    typedef bool (*ReleaseFdFn)(int);

    void TunSafeSetCallbacks(
        ConfigureTunFn      configureTun,
        OnConnectedFn       onConnected,
        OnConnectionRetryFn onConnectionRetry,
        OnPingReplyFn       onPingReply,
        OnRequestTokenFn    onRequestToken,
        ProtectFdFn         protectFd,
        ReleaseFdFn         releaseFd
    );
}

// ── C++ → Java callbacks ──────────────────────────────────────────────────────

// Helper: attach current thread to JVM, returns env or nullptr.
static JNIEnv* getEnv(bool* did_attach) {
    JNIEnv* env = nullptr;
    *did_attach = false;
    int st = g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (st == JNI_EDETACHED) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
            *did_attach = true;
        } else {
            return nullptr;
        }
    }
    return env;
}

static int cb_configureTun(const char* config) {
    bool attached;
    JNIEnv* env = getEnv(&attached);
    if (!env || !g_cb.obj) return -1;

    jobject obj = env->NewLocalRef(g_cb.obj);
    if (!obj) { if (attached) g_jvm->DetachCurrentThread(); return -1; }

    jstring jconfig = env->NewStringUTF(config ? config : "");
    jint result = env->CallIntMethod(obj, g_cb.configureTun, jconfig);
    env->DeleteLocalRef(jconfig);
    env->DeleteLocalRef(obj);

    if (attached) g_jvm->DetachCurrentThread();
    return (int)result;
}

static void cb_onConnected() {
    bool attached;
    JNIEnv* env = getEnv(&attached);
    if (!env || !g_cb.obj) return;
    jobject obj = env->NewLocalRef(g_cb.obj);
    if (obj) { env->CallVoidMethod(obj, g_cb.onConnected); env->DeleteLocalRef(obj); }
    if (attached) g_jvm->DetachCurrentThread();
}

static void cb_onConnectionRetry(int delay_sec) {
    bool attached;
    JNIEnv* env = getEnv(&attached);
    if (!env || !g_cb.obj) return;
    jobject obj = env->NewLocalRef(g_cb.obj);
    if (obj) { env->CallVoidMethod(obj, g_cb.onConnectionRetry, (jint)delay_sec); env->DeleteLocalRef(obj); }
    if (attached) g_jvm->DetachCurrentThread();
}

static void cb_onPingReply(const char* ip, int latency_ms) {
    bool attached;
    JNIEnv* env = getEnv(&attached);
    if (!env || !g_cb.obj) return;
    jobject obj = env->NewLocalRef(g_cb.obj);
    if (obj) {
        jstring jip = env->NewStringUTF(ip ? ip : "");
        env->CallVoidMethod(obj, g_cb.onPingReply, jip, (jint)latency_ms);
        env->DeleteLocalRef(jip);
        env->DeleteLocalRef(obj);
    }
    if (attached) g_jvm->DetachCurrentThread();
}

static void cb_onRequestToken(int type) {
    bool attached;
    JNIEnv* env = getEnv(&attached);
    if (!env || !g_cb.obj) return;
    jobject obj = env->NewLocalRef(g_cb.obj);
    if (obj) { env->CallVoidMethod(obj, g_cb.onRequestToken, (jint)type); env->DeleteLocalRef(obj); }
    if (attached) g_jvm->DetachCurrentThread();
}

static void cb_protectFd(int fd) {
    bool attached;
    JNIEnv* env = getEnv(&attached);
    if (!env || !g_cb.obj) return;
    jobject obj = env->NewLocalRef(g_cb.obj);
    if (obj) { env->CallVoidMethod(obj, g_cb.protectFd, (jint)fd); env->DeleteLocalRef(obj); }
    if (attached) g_jvm->DetachCurrentThread();
}

static bool cb_releaseFd(int fd) {
    bool attached;
    JNIEnv* env = getEnv(&attached);
    if (!env || !g_cb.obj) return false;
    jobject obj = env->NewLocalRef(g_cb.obj);
    jboolean result = JNI_FALSE;
    if (obj) {
        result = env->CallBooleanMethod(obj, g_cb.releaseFd, (jint)fd);
        env->DeleteLocalRef(obj);
    }
    if (attached) g_jvm->DetachCurrentThread();
    return (bool)result;
}

// ── JNI_OnLoad ────────────────────────────────────────────────────────────────

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    g_jvm = vm;
    LOGI("TunSafe JNI loaded");
    return JNI_VERSION_1_6;
}

// ── JNI exports ───────────────────────────────────────────────────────────────
// All methods live on com.tunsafe.service.TunsafeVpnService
// Naming convention: Java_<package_underscored>_<ClassName>_<methodName>

extern "C" {

// nativeInitialize(NativeCallbacks callbacks) → int
// Called once when the VpnService is created.
// Caches JNI method IDs and registers C++ callbacks.
JNIEXPORT jint JNICALL
Java_com_tunsafe_service_TunsafeVpnService_nativeInitialize(
        JNIEnv* env, jobject /*thiz*/, jobject callbacks) {

    if (!callbacks) {
        LOGE("nativeInitialize: null callbacks");
        return -1;
    }

    // Cache weak reference to callbacks object
    if (g_cb.obj) env->DeleteWeakGlobalRef(g_cb.obj);
    g_cb.obj = env->NewWeakGlobalRef(callbacks);

    // Resolve method IDs on NativeCallbacks
    jclass cls = env->GetObjectClass(callbacks);
    if (!cls) { LOGE("nativeInitialize: can't get NativeCallbacks class"); return -1; }

    g_cb.configureTun      = env->GetMethodID(cls, "configureTun",      "(Ljava/lang/String;)I");
    g_cb.onConnected       = env->GetMethodID(cls, "onConnected",       "()V");
    g_cb.onConnectionRetry = env->GetMethodID(cls, "onConnectionRetry", "(I)V");
    g_cb.onPingReply       = env->GetMethodID(cls, "onPingReply",       "(Ljava/lang/String;I)V");
    g_cb.onRequestToken    = env->GetMethodID(cls, "onRequestToken",    "(I)V");
    g_cb.protectFd         = env->GetMethodID(cls, "protectFd",         "(I)V");
    g_cb.releaseFd         = env->GetMethodID(cls, "releaseFd",         "(I)Z");

    env->DeleteLocalRef(cls);

    if (!g_cb.configureTun || !g_cb.onConnected || !g_cb.onConnectionRetry ||
        !g_cb.onPingReply  || !g_cb.onRequestToken || !g_cb.protectFd || !g_cb.releaseFd) {
        LOGE("nativeInitialize: failed to resolve one or more method IDs");
        return -1;
    }

    // Register callbacks with the C++ core
    TunSafeSetCallbacks(
        cb_configureTun,
        cb_onConnected,
        cb_onConnectionRetry,
        cb_onPingReply,
        cb_onRequestToken,
        cb_protectFd,
        cb_releaseFd
    );

    LOGI("nativeInitialize: OK");
    return 0;
}

// start(String config, boolean killSwitch) → int
JNIEXPORT jint JNICALL
Java_com_tunsafe_service_TunsafeVpnService_start(
        JNIEnv* env, jobject /*thiz*/, jstring jconfig, jboolean kill_switch) {

    if (!jconfig) { LOGE("start: null config"); return -1; }
    const char* config = env->GetStringUTFChars(jconfig, nullptr);
    LOGI("start: config len=%zu kill_switch=%d", strlen(config), (int)kill_switch);
    int ret = TunSafeStart(config, (bool)kill_switch);
    env->ReleaseStringUTFChars(jconfig, config);
    return ret;
}

// getLogLines() → String
JNIEXPORT jstring JNICALL
Java_com_tunsafe_service_TunsafeVpnService_getLogLines(
        JNIEnv* env, jobject /*thiz*/) {

    char* log = TunSafeGetLog();
    jstring result = env->NewStringUTF(log ? log : "");
    free(log);
    return result;
}

// getStats(TunsafeVpnService.Stats stats) → void
// Fills stats.rxBytes, stats.txBytes, stats.connectionTime
JNIEXPORT void JNICALL
Java_com_tunsafe_service_TunsafeVpnService_getStats(
        JNIEnv* env, jobject /*thiz*/, jobject jstats) {

    if (!jstats) return;

    int64_t rx = 0, tx = 0, conn_time = 0;
    TunSafeGetStats(&rx, &tx, &conn_time);

    jclass cls = env->GetObjectClass(jstats);
    jfieldID fRx   = env->GetFieldID(cls, "rxBytes",        "J");
    jfieldID fTx   = env->GetFieldID(cls, "txBytes",        "J");
    jfieldID fTime = env->GetFieldID(cls, "connectionTime", "J");
    env->DeleteLocalRef(cls);

    if (fRx)   env->SetLongField(jstats, fRx,   (jlong)rx);
    if (fTx)   env->SetLongField(jstats, fTx,   (jlong)tx);
    if (fTime) env->SetLongField(jstats, fTime, (jlong)conn_time);
}

// getPublicKey(String privateKeyBase64) → String
JNIEXPORT jstring JNICALL
Java_com_tunsafe_service_TunsafeVpnService_getPublicKey(
        JNIEnv* env, jobject /*thiz*/, jstring jprivkey) {

    char buf[64] = {};
    if (jprivkey) {
        const char* privkey = env->GetStringUTFChars(jprivkey, nullptr);
        TunSafeGetPublicKey(privkey, buf);
        env->ReleaseStringUTFChars(jprivkey, privkey);
    }
    return env->NewStringUTF(buf);
}

// getPrivateKey() → String   (generates a fresh private key)
JNIEXPORT jstring JNICALL
Java_com_tunsafe_service_TunsafeVpnService_getPrivateKey(
        JNIEnv* env, jobject /*thiz*/) {

    char buf[64] = {};
    TunSafeGeneratePrivateKey(buf);
    return env->NewStringUTF(buf);
}

// getExternalIp(String serverHint) → String
JNIEXPORT jstring JNICALL
Java_com_tunsafe_service_TunsafeVpnService_getExternalIp(
        JNIEnv* env, jobject /*thiz*/, jstring jserver) {

    char buf[64] = {};
    if (jserver) {
        const char* server = env->GetStringUTFChars(jserver, nullptr);
        TunSafeGetExternalIp(server, buf, sizeof(buf));
        env->ReleaseStringUTFChars(jserver, server);
    }
    return env->NewStringUTF(buf);
}

// nativePing(String server) → boolean
JNIEXPORT jboolean JNICALL
Java_com_tunsafe_service_TunsafeVpnService_nativePing(
        JNIEnv* env, jobject /*thiz*/, jstring jserver) {

    if (!jserver) return JNI_FALSE;
    const char* server = env->GetStringUTFChars(jserver, nullptr);
    bool ok = TunSafePing(server);
    env->ReleaseStringUTFChars(jserver, server);
    return ok ? JNI_TRUE : JNI_FALSE;
}

// setPingServer(String server) → boolean
JNIEXPORT jboolean JNICALL
Java_com_tunsafe_service_TunsafeVpnService_setPingServer(
        JNIEnv* env, jobject /*thiz*/, jstring jserver) {

    if (!jserver) return JNI_FALSE;
    const char* server = env->GetStringUTFChars(jserver, nullptr);
    bool ok = TunSafeSetPingServer(server);
    env->ReleaseStringUTFChars(jserver, server);
    return ok ? JNI_TRUE : JNI_FALSE;
}

// submitToken(String token) → void
JNIEXPORT void JNICALL
Java_com_tunsafe_service_TunsafeVpnService_submitToken(
        JNIEnv* env, jobject /*thiz*/, jstring jtoken) {

    if (!jtoken) return;
    const char* token = env->GetStringUTFChars(jtoken, nullptr);
    TunSafeSubmitToken(token);
    env->ReleaseStringUTFChars(jtoken, token);
}

// retrynow() → void
JNIEXPORT void JNICALL
Java_com_tunsafe_service_TunsafeVpnService_retrynow(
        JNIEnv* env, jobject /*thiz*/) {
    TunSafeRetryNow();
}

// nativeCloseFd(int fd) → void
JNIEXPORT void JNICALL
Java_com_tunsafe_service_TunsafeVpnService_nativeCloseFd(
        JNIEnv* /*env*/, jobject /*thiz*/, jint fd) {
    TunSafeCloseFd((int)fd);
}

// nativePurgeFd(int fd) → void
JNIEXPORT void JNICALL
Java_com_tunsafe_service_TunsafeVpnService_nativePurgeFd(
        JNIEnv* /*env*/, jobject /*thiz*/, jint fd) {
    TunSafePurgeFd((int)fd);
}

// postexit(boolean graceful) → void
JNIEXPORT void JNICALL
Java_com_tunsafe_service_TunsafeVpnService_postexit(
        JNIEnv* /*env*/, jobject /*thiz*/, jboolean graceful) {
    TunSafePostExit((bool)graceful);
}

} // extern "C"
