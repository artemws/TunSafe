// network_android.cpp
// Android platform backend for TunSafe.
// Replaces tunsafe_bsd.cpp (which uses open_tun/GetDefaultRoute — Linux-only).
//
// The WireGuard engine from network_bsd.cpp handles all crypto and packet I/O.
// This file wires it to Android's VpnService via the JNI callbacks.

#include "build_config.h"
#include "tunsafe_types.h"
#include "wireguard.h"
#include "wireguard_config.h"
#include "network_bsd.h"
#include "tunsafe_threading.h"
#include "util.h"

#include <android/log.h>
#include <string>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define LOG_TAG "TunSafeNet"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Declared in tunsafe_android.cpp — routes to Java callbacks
extern int  AndroidConfigureTun(const char* config);
extern void AndroidOnConnected();
extern void AndroidOnConnectionRetry(int delay);
extern void AndroidOnPingReply(const char* ip, int ms);
extern void AndroidOnRequestToken(int type);
extern void AndroidProtectFd(int fd);
extern bool AndroidReleaseFd(int fd);
extern void AndroidUpdateStats(int64_t rx, int64_t tx, int64_t conn_time_sec);

// ── WireGuard engine state ────────────────────────────────────────────────────

static WireguardProcessor* g_wg = nullptr;
static pthread_mutex_t     g_wg_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile bool       g_stop_requested = false;

// Current tun fd (provided by Android VpnService via configureTun callback)
static int g_tun_fd = -1;

// ── Platform callbacks called by the BSD network engine ───────────────────────
// network_bsd.cpp calls these when it needs platform services.

// Called when the engine wants to open a tun interface.
// On Android the tun fd comes from VpnService.Builder.establish() via Java;
// we trigger that by calling AndroidConfigureTun with the WireGuard config.
extern "C" int platform_open_tun(const char* config_str, int* out_fd) {
    int fd = AndroidConfigureTun(config_str);
    if (fd < 0) {
        LOGE("platform_open_tun: AndroidConfigureTun returned %d", fd);
        return -1;
    }
    g_tun_fd = fd;
    *out_fd = fd;
    return 0;
}

// Called when the engine opens a UDP/TCP socket — protect it from the VPN.
extern "C" void platform_protect_fd(int fd) {
    AndroidProtectFd(fd);
}

// Called when the engine is connected.
extern "C" void platform_on_connected() {
    LOGI("WireGuard connected");
    AndroidOnConnected();
}

// Called on connection retry.
extern "C" void platform_on_connection_retry(int delay_sec) {
    LOGI("WireGuard retry in %d s", delay_sec);
    AndroidOnConnectionRetry(delay_sec);
}

// Called with updated stats (bytes + uptime).
extern "C" void platform_update_stats(int64_t rx, int64_t tx, int64_t conn_time_sec) {
    AndroidUpdateStats(rx, tx, conn_time_sec);
}

// ── Engine lifecycle ──────────────────────────────────────────────────────────

static WireguardProcessor* CreateEngine(const char* config_str, bool kill_switch) {
    WireguardProcessor* wg = new WireguardProcessor(nullptr, nullptr, nullptr);
    if (!wg) return nullptr;

    WgConfig cfg;
    if (!ParseWireGuardConfiguration(&cfg, config_str)) {
        LOGE("Failed to parse WireGuard config");
        delete wg;
        return nullptr;
    }
    (void)kill_switch; // TODO: implement kill-switch via VpnService setBlocking / Android firewall rules
    wg->ConfigureWithConfig(cfg);
    return wg;
}

void WireGuardNetworkStart(const char* config, bool kill_switch) {
    g_stop_requested = false;

    pthread_mutex_lock(&g_wg_mutex);
    if (g_wg) { delete g_wg; g_wg = nullptr; }
    g_wg = CreateEngine(config, kill_switch);
    pthread_mutex_unlock(&g_wg_mutex);

    if (!g_wg) { LOGE("Engine creation failed"); return; }

    // Run the BSD event loop (polls tun + UDP sockets)
    // network_bsd.cpp's RunLoop blocks until stopped.
    extern void BsdNetworkRunLoop(WireguardProcessor* wg, volatile bool* stop);
    BsdNetworkRunLoop(g_wg, &g_stop_requested);

    pthread_mutex_lock(&g_wg_mutex);
    delete g_wg;
    g_wg = nullptr;
    pthread_mutex_unlock(&g_wg_mutex);
}

void WireGuardNetworkStop() {
    g_stop_requested = true;
    // Wake up the event loop
    pthread_mutex_lock(&g_wg_mutex);
    if (g_wg) g_wg->WakeUp();
    pthread_mutex_unlock(&g_wg_mutex);
}

bool WireGuardNetworkPing(const char* server) {
    pthread_mutex_lock(&g_wg_mutex);
    bool ok = g_wg && g_wg->SendPing(server);
    pthread_mutex_unlock(&g_wg_mutex);
    return ok;
}

bool WireGuardNetworkSetPingServer(const char* server) {
    pthread_mutex_lock(&g_wg_mutex);
    bool ok = g_wg && g_wg->SetPingServer(server);
    pthread_mutex_unlock(&g_wg_mutex);
    return ok;
}

void WireGuardNetworkRetryNow() {
    pthread_mutex_lock(&g_wg_mutex);
    if (g_wg) g_wg->RetryNow();
    pthread_mutex_unlock(&g_wg_mutex);
}

void WireGuardNetworkSubmitToken(const char* token) {
    pthread_mutex_lock(&g_wg_mutex);
    if (g_wg) g_wg->SubmitToken(token);
    pthread_mutex_unlock(&g_wg_mutex);
}

void WireGuardNetworkCloseFd(int fd) {
    if (fd == g_tun_fd) g_tun_fd = -1;
    close(fd);
}

void WireGuardNetworkPurgeFd(int fd) {
    (void)fd; // fd will be recycled by the OS
}

void WireGuardNetworkPostExit(bool graceful) {
    if (graceful) WireGuardNetworkStop();
    else g_stop_requested = true;
}
