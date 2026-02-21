// network_android.cpp
// Android WireGuard backend — mirrors TunsafeBackendBsdImpl from tunsafe_bsd.cpp.
// Replaces open_tun() with the tun fd supplied by Android VpnService via JNI.

#include "build_config.h"
#include "wireguard.h"
#include "wireguard_config.h"
#include "tunsafe_wg_plugin.h"
#include "network_bsd.h"
#include "network_common.h"
#include "netapi.h"
#include "tunsafe_ipaddr.h"
#include "tunsafe_threading.h"
#include "tunsafe_dnsresolve.h"
#include "util.h"

#include <android/log.h>
#include <signal.h>
#include <pthread.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <unistd.h>

#define LOG_TAG "TunSafeNet"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Declared in tunsafe_android.cpp
extern int  AndroidConfigureTun(const char* config_str);
extern void AndroidOnConnected();
extern void AndroidOnConnectionRetry(int delay);

// ── Android backend ───────────────────────────────────────────────────────────

class AndroidBackend
    : public TunInterface,
      public UdpInterface,
      public ProcessorDelegate,
      public PluginDelegate,
      public NetworkBsd::NetworkBsdDelegate {
public:
    AndroidBackend();
    ~AndroidBackend();

    bool Run(const char* config_str);
    void Stop();

    // TunInterface
    bool Configure(const TunConfig&& config, TunConfigOut* out) override;
    void WriteTunPacket(Packet* packet) override;

    // UdpInterface
    bool Configure(int listen_port_udp, int listen_port_tcp) override;
    void WriteUdpPacket(Packet* packet) override;

    // ProcessorDelegate
    void OnConnected() override;
    void OnConnectionRetry(uint32 attempts) override;

    // PluginDelegate
    void OnRequestToken(WgPeer* peer, uint32 type) override;

    // NetworkBsdDelegate
    void OnSecondLoop(uint64 now) override;
    void RunAllMainThreadScheduled() override;

private:
    TunsafePlugin*     plugin_;
    WireguardProcessor processor_;
    NetworkBsd         network_;
    TunSocketBsd       tun_;
    UdpSocketBsd       udp_;
};

AndroidBackend::AndroidBackend()
    : plugin_(nullptr),
      processor_(this, this, this),   // UdpInterface, TunInterface, ProcessorDelegate
      network_(this, 1000),
      tun_(&network_, &processor_),
      udp_(&network_, &processor_) {
    plugin_ = CreateTunsafePlugin(this, &processor_);
    processor_.dev().SetPlugin(plugin_);
}

AndroidBackend::~AndroidBackend() {
    delete plugin_;
}

// TunInterface::Configure — called by WireguardProcessor when config is parsed.
// We pass address/DNS/MTU info to Java so it can call VpnService.Builder.establish().
bool AndroidBackend::Configure(const TunConfig&& config, TunConfigOut* out) {
    char buf[128];
    std::string tun_config;

    for (const auto& addr : config.addresses) {
        if (addr.size == 4) {
            snprintf(buf, sizeof(buf), "Address=%u.%u.%u.%u/%d\n",
                     addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3], addr.cidr);
            tun_config += buf;
        }
    }
    for (const auto& dns : config.dns) {
        if (dns.sin_family == AF_INET) {
            const uint8_t* b = reinterpret_cast<const uint8_t*>(&dns.sin.sin_addr);
            snprintf(buf, sizeof(buf), "DNS=%u.%u.%u.%u\n", b[0], b[1], b[2], b[3]);
            tun_config += buf;
        }
    }
    snprintf(buf, sizeof(buf), "MTU=%d\n", config.mtu > 0 ? config.mtu : 1420);
    tun_config += buf;

    if (out) {
        out->enable_neighbor_discovery_spoofing = false;
        memset(out->neighbor_discovery_spoofing_mac, 0, 6);
    }

    int tun_fd = AndroidConfigureTun(tun_config.c_str());
    if (tun_fd < 0) {
        LOGE("AndroidConfigureTun failed: %d", tun_fd);
        return false;
    }
    if (!tun_.Initialize(tun_fd)) {
        LOGE("TunSocketBsd::Initialize failed");
        close(tun_fd);
        return false;
    }
    LOGI("TUN fd=%d configured", tun_fd);
    return true;
}

void AndroidBackend::WriteTunPacket(Packet* packet) {
    tun_.WritePacket(packet);
}

bool AndroidBackend::Configure(int listen_port_udp, int /*listen_port_tcp*/) {
    return udp_.Initialize(listen_port_udp);
}

void AndroidBackend::WriteUdpPacket(Packet* packet) {
    udp_.WritePacket(packet);
}

void AndroidBackend::OnConnected() {
    LOGI("Connected");
    AndroidOnConnected();
}

void AndroidBackend::OnConnectionRetry(uint32 attempts) {
    LOGI("Retry (attempts=%u)", attempts);
    AndroidOnConnectionRetry((int)attempts);
}

void AndroidBackend::OnRequestToken(WgPeer* /*peer*/, uint32 /*type*/) {
    // Token submission is handled via TunSafeSubmitToken → SubmitToken on plugin
}

void AndroidBackend::OnSecondLoop(uint64 /*now*/) {
    processor_.SecondLoop();
}

void AndroidBackend::RunAllMainThreadScheduled() {
    processor_.RunAllMainThreadScheduled();
}

bool AndroidBackend::Run(const char* config_str) {
    DnsResolver dns_resolver(nullptr);

    if (!ParseWireGuardConfigString(&processor_, config_str, strlen(config_str), &dns_resolver)) {
        LOGE("Failed to parse WireGuard config");
        return false;
    }
    if (!processor_.Start()) {
        LOGE("WireguardProcessor::Start() failed");
        return false;
    }

    sigset_t sigmask;
    sigemptyset(&sigmask);
    network_.RunLoop(&sigmask);
    return true;
}

void AndroidBackend::Stop() {
    *network_.exit_flag() = true;
}

// ── Global singleton ──────────────────────────────────────────────────────────

static AndroidBackend* g_backend = nullptr;
static pthread_mutex_t g_backend_mutex = PTHREAD_MUTEX_INITIALIZER;

void WireGuardNetworkStart(const char* config, bool /*kill_switch*/) {
    AndroidBackend* backend = new AndroidBackend();

    pthread_mutex_lock(&g_backend_mutex);
    if (g_backend) { delete g_backend; }
    g_backend = backend;
    pthread_mutex_unlock(&g_backend_mutex);

    backend->Run(config);  // blocks until Stop()

    pthread_mutex_lock(&g_backend_mutex);
    if (g_backend == backend) g_backend = nullptr;
    pthread_mutex_unlock(&g_backend_mutex);

    delete backend;
}

void WireGuardNetworkStop() {
    pthread_mutex_lock(&g_backend_mutex);
    AndroidBackend* b = g_backend;
    pthread_mutex_unlock(&g_backend_mutex);
    if (b) b->Stop();
}

void WireGuardNetworkRetryNow()                         { WireGuardNetworkStop(); }
bool WireGuardNetworkPing(const char*)                  { return false; }
bool WireGuardNetworkSetPingServer(const char*)         { return false; }
void WireGuardNetworkSubmitToken(const char* /*token*/) {}
void WireGuardNetworkCloseFd(int fd)                    { close(fd); }
void WireGuardNetworkPurgeFd(int)                       {}
void WireGuardNetworkPostExit(bool)                     { WireGuardNetworkStop(); }
