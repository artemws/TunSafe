// SPDX-License-Identifier: AGPL-1.0-only
// TunSafe Android JNI bridge.
//
// This file glues the Android VpnService (Java) to the TunSafe C++ core.
//
// Architecture:
//   Java VpnService  ──JNI──►  tunsafe_android.cpp
//                                    │
//                                    ▼
//                          TunsafeBackendAndroid
//                          (subclass of TunsafeBackendBsd)
//                                    │
//                         ┌──────────┴───────────┐
//                         ▼                       ▼
//                  network_bsd.cpp          network_common.cpp
//               (TCP/UDP/poll loop)       (TLS obfuscation)
//
// Java side responsibilities:
//   • Call VpnService.establish() and pass the resulting fd via jniStart()
//   • Call VpnService.protect() for every fd via the protect callback
//   • Run jniStart() on a background thread (it blocks until VPN stops)
//
// C++ side responsibilities:
//   • Open /dev/tun is skipped — fd comes from Java
//   • Route management is skipped — Android handles routes via VpnService.Builder
//   • All socket protect() calls go back to Java via g_protect_socket callback

#include "build_config.h"

#ifdef OS_ANDROID

#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <string>

#include "wireguard.h"
#include "wireguard_config.h"
#include "network_bsd.h"
#include "tunsafe_bsd.h"
#include "util.h"
#include "netapi.h"

#define LOG_TAG "TunSafe"
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Socket protect callback — set by Java before starting the VPN loop.
// Called with an fd that must be protected from the VPN tunnel.
// ---------------------------------------------------------------------------
static JavaVM *g_jvm = NULL;

// Java object that has the protect(int) method (the VpnService subclass).
static jobject g_vpn_service_obj = NULL;
static jmethodID g_protect_method = NULL;

// Called from C++ network layer to protect a socket fd from the VPN tunnel.
// Must be callable from any thread.
static bool android_protect_socket(int fd) {
  if (!g_jvm || !g_vpn_service_obj || !g_protect_method)
    return false;

  JNIEnv *env = NULL;
  bool attached = false;
  int ret = g_jvm->GetEnv((void **)&env, JNI_VERSION_1_6);
  if (ret == JNI_EDETACHED) {
    if (g_jvm->AttachCurrentThread(&env, NULL) != 0)
      return false;
    attached = true;
  } else if (ret != JNI_OK) {
    return false;
  }

  jboolean ok = env->CallBooleanMethod(g_vpn_service_obj, g_protect_method, (jint)fd);

  if (attached)
    g_jvm->DetachCurrentThread();

  return ok == JNI_TRUE;
}

// Android-specific logging override
// tunsafe_die is already defined in network_bsd.cpp;
// on Android we override RINFO/RERROR only.

// ---------------------------------------------------------------------------
// TunsafeBackendAndroid
//
// Subclass of TunsafeBackendBsd that:
//   • Accepts the TUN fd from Java instead of opening /dev/tun
//   • Calls android_protect_socket() for UDP and outgoing TCP sockets
//   • Skips route management (Android VpnService.Builder handles routes)
// ---------------------------------------------------------------------------
class TunsafeBackendAndroid
    : public TunsafeBackendBsd,
      public NetworkBsd::NetworkBsdDelegate,
      public ProcessorDelegate,
      public PluginDelegate {
public:
  explicit TunsafeBackendAndroid(int tun_fd);
  virtual ~TunsafeBackendAndroid();

  void RunLoop();

  // -- from TunInterface
  virtual void WriteTunPacket(Packet *packet) override;

  // -- from UdpInterface
  virtual bool Configure(int listen_port_udp, int listen_port_tcp) override;
  virtual void WriteUdpPacket(Packet *packet) override;
  virtual void CloseOutgoingTcpForAddr(const IpAddr &addr) override;

  // -- from NetworkBsdDelegate
  virtual void OnSecondLoop(uint64 now) override;
  virtual void RunAllMainThreadScheduled() override;

  // -- from ProcessorDelegate
  virtual void OnConnected(WgPeer *peer) override;
  virtual void OnConnectionRetry(WgPeer *peer, uint32 attempts) override;

  // -- from PluginDelegate
  virtual void OnRequestToken(WgPeer *peer, uint32 type) override {}

  WireguardProcessor *processor() { return &processor_; }

protected:
  // InitializeTun is overridden to use the fd from Java instead of open_tun().
  virtual bool InitializeTun(char devname[16]) override;

private:
  void CloseOrphanTcpConnections();

  int       tun_fd_;
  bool      is_connected_;
  uint8     close_orphan_counter_;
  TunsafePlugin       *plugin_;
  WireguardProcessor   processor_;
  NetworkBsd           network_;
  TunSocketBsd         tun_;
  UdpSocketBsd         udp_;
  TcpSocketListenerBsd tcp_listener_;
};

TunsafeBackendAndroid::TunsafeBackendAndroid(int tun_fd)
    : tun_fd_(tun_fd),
      is_connected_(false),
      close_orphan_counter_(0),
      plugin_(CreateTunsafePlugin(this, &processor_)),
      processor_(this, this, this),
      network_(this, 1000),
      tun_(&network_, &processor_),
      udp_(&network_, &processor_),
      tcp_listener_(&network_, &processor_) {
  processor_.dev().SetPlugin(plugin_);
}

TunsafeBackendAndroid::~TunsafeBackendAndroid() {
  delete plugin_;
}

// Use the TUN fd given to us by Java VpnService.establish()
// instead of open_tun() which requires root / /dev/tun access.
bool TunsafeBackendAndroid::InitializeTun(char devname[16]) {
  snprintf(devname, 16, "tun0");
  if (!tun_.Initialize(tun_fd_)) {
    ALOGE("TunSocketBsd::Initialize failed for fd %d", tun_fd_);
    return false;
  }
  tun_fd_ = -1;   // TunSocketBsd now owns the fd
  return true;
}

void TunsafeBackendAndroid::WriteTunPacket(Packet *packet) {
  tun_.WritePacket(packet);
}

bool TunsafeBackendAndroid::Configure(int listen_port_udp, int listen_port_tcp) {
  if (!udp_.Initialize(listen_port_udp))
    return false;

  // Protect the UDP socket so its traffic bypasses the VPN tunnel.
  android_protect_socket(udp_.GetFd());

  if (listen_port_tcp != 0) {
    if (!tcp_listener_.Initialize(listen_port_tcp))
      return false;
    // TCP listener socket also needs protect().
    android_protect_socket(tcp_listener_.GetFd());
  }
  return true;
}

void TunsafeBackendAndroid::WriteUdpPacket(Packet *packet) {
  if (packet->protocol & kPacketProtocolTcp) {
    // Outgoing TCP socket is created lazily in WriteTcpPacket.
    // We hook socket creation to call protect() via TcpSocketBsd::InitializeOutgoing.
    TcpSocketBsd::WriteTcpPacket(&network_, &processor_, packet);
  } else {
    udp_.WritePacket(packet);
  }
}

void TunsafeBackendAndroid::CloseOutgoingTcpForAddr(const IpAddr &addr) {
  char buf[kSizeOfAddress];
  for (TcpSocketBsd *tcp = network_.tcp_sockets(); tcp; tcp = tcp->next()) {
    if (tcp->endpoint_protocol() == kPacketProtocolTcp &&
        CompareIpAddr(&tcp->endpoint(), &addr) == 0) {
      uint8 rnd; OsGetRandomBytes(&rnd, 1);
      uint32 delay = 2 + (rnd % 7);
      tcp->SetDeferredClose((uint32)(OsGetMilliseconds() / 1000) + delay);
      ALOGI("hybrid_tcp: TCP to %s will close in %us", PrintIpAddr(addr, buf), delay);
      return;
    }
  }
}

void TunsafeBackendAndroid::OnSecondLoop(uint64 now) {
  if (!(close_orphan_counter_++ & 0xF))
    CloseOrphanTcpConnections();
  processor_.SecondLoop();
}

void TunsafeBackendAndroid::RunAllMainThreadScheduled() {
  processor_.RunAllMainThreadScheduled();
}

void TunsafeBackendAndroid::OnConnected(WgPeer *peer) {
  char buf[kSizeOfAddress], peer_buf[kSizeOfAddress];
  const char *peer_str = "(unknown)";
  if (peer) {
    const IpAddr &ep = peer->endpoint();
    if (ep.sin.sin_family != 0)
      peer_str = PrintIpAddr(ep, peer_buf);
  }
  if (!is_connected_) {
    const WgCidrAddr *ipv4_addr = NULL;
    for (const WgCidrAddr &x : processor_.addr()) {
      if (x.size == 32) { ipv4_addr = &x; break; }
    }
    uint32 ipv4_ip = ipv4_addr ? ReadBE32(ipv4_addr->addr) : 0;
    ALOGI("Connection established. IP %s, peer %s",
          ipv4_ip ? print_ip(buf, ipv4_ip) : "(none)", peer_str);
    is_connected_ = true;
  }
}

void TunsafeBackendAndroid::OnConnectionRetry(WgPeer *peer, uint32 attempts) {
  if (attempts == 4)
    ALOGI("Connecting...");
}

void TunsafeBackendAndroid::CloseOrphanTcpConnections() {
  // Collect all peer endpoints that are TCP-based.
  std::vector<IpAddr> active_endpoints;
  for (WgPeer *peer = processor_.dev().first_peer(); peer; peer = peer->next_peer()) {
    if (peer->endpoint_protocol() & kPacketProtocolTcp)
      active_endpoints.push_back(peer->endpoint());
  }
  // Close any outgoing TCP socket whose endpoint is not in the active set.
  for (TcpSocketBsd *tcp = network_.tcp_sockets(); tcp; tcp = tcp->next()) {
    if (tcp->endpoint_protocol() & kPacketProtocolIncomingConnection)
      continue;
    bool found = false;
    for (const IpAddr &ep : active_endpoints) {
      if (CompareIpAddr(&tcp->endpoint(), &ep) == 0) { found = true; break; }
    }
    if (!found) {
      char buf[kSizeOfAddress];
      ALOGI("Closing orphan TCP connection to %s", PrintIpAddr(tcp->endpoint(), buf));
      tcp->SetDeferredClose((uint32)(OsGetMilliseconds() / 1000));
    }
  }
}

void TunsafeBackendAndroid::RunLoop() {
  network_.RunLoop(NULL);  // NULL = no signal mask on Android
}

// ---------------------------------------------------------------------------
// Android-specific: protect newly created outgoing TCP sockets.
//
// We hook TcpSocketBsd::InitializeOutgoing() by overriding it globally for
// Android via a weak symbol. The real implementation calls protect() right
// after socket() succeeds.
//
// Because TcpSocketBsd::InitializeOutgoing is defined in network_bsd.cpp,
// we can't easily override it. Instead we add a call site hook:
// NetworkBsd calls OnNewOutgoingTcpSocket() on its delegate.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// JNI entry points
// ---------------------------------------------------------------------------

// Global backend instance — only one VPN session at a time.
static TunsafeBackendAndroid *g_backend = NULL;
static pthread_mutex_t g_backend_mutex = PTHREAD_MUTEX_INITIALIZER;

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  g_jvm = vm;
  return JNI_VERSION_1_6;
}

// Java: native void jniStart(FileDescriptor tunFd, String config)
//
// Blocks until the VPN session ends. Call from a background thread.
JNIEXPORT void JNICALL
Java_com_tunsafe_app_TunSafeService_jniStart(
    JNIEnv *env,
    jobject service,
    jobject tun_fd_obj,
    jstring config_jstr) {

  // Get the raw fd from the FileDescriptor object.
  jclass fd_class = env->FindClass("java/io/FileDescriptor");
  jfieldID fd_field = env->GetFieldID(fd_class, "descriptor", "I");
  int tun_fd = env->GetIntField(tun_fd_obj, fd_field);

  if (tun_fd < 0) {
    ALOGE("jniStart: invalid tun fd %d", tun_fd);
    return;
  }

  // Duplicate the fd — Java will close the original FileDescriptor.
  tun_fd = dup(tun_fd);
  if (tun_fd < 0) {
    ALOGE("jniStart: dup() failed: %s", strerror(errno));
    return;
  }
  fcntl(tun_fd, F_SETFD, FD_CLOEXEC);

  // Save VpnService reference for protect() calls.
  jclass svc_class = env->GetObjectClass(service);
  g_protect_method = env->GetMethodID(svc_class, "protect", "(I)Z");
  g_vpn_service_obj = env->NewGlobalRef(service);

  // Parse config string.
  const char *config_c = env->GetStringUTFChars(config_jstr, NULL);
  std::string config_str(config_c ? config_c : "");
  env->ReleaseStringUTFChars(config_jstr, config_c);

  // Create backend.
  pthread_mutex_lock(&g_backend_mutex);
  if (g_backend) {
    ALOGE("jniStart: already running");
    pthread_mutex_unlock(&g_backend_mutex);
    close(tun_fd);
    return;
  }
  g_backend = new TunsafeBackendAndroid(tun_fd);
  pthread_mutex_unlock(&g_backend_mutex);

  WireguardProcessor *proc = g_backend->processor();

  // Parse WireGuard config.
  if (!ParseWireGuardConfigString(proc, config_str.c_str(), config_str.size(), NULL)) {
    ALOGE("jniStart: config parse failed");
    goto cleanup;
  }

  // Initialize obfuscation.
  if (proc->dev().packet_obfuscator().enabled())
    ALOGI("TCP obfuscation enabled");

  // Start.
  if (!proc->Start()) {
    ALOGE("jniStart: WireguardProcessor::Start() failed");
    goto cleanup;
  }

  ALOGI("jniStart: entering run loop");
  g_backend->RunLoop();
  ALOGI("jniStart: run loop exited");

cleanup:
  pthread_mutex_lock(&g_backend_mutex);
  delete g_backend;
  g_backend = NULL;
  pthread_mutex_unlock(&g_backend_mutex);

  env->DeleteGlobalRef(g_vpn_service_obj);
  g_vpn_service_obj = NULL;
  g_protect_method = NULL;
}

// Java: native void jniStop()
//
// Signal the run loop to exit. Safe to call from any thread.
JNIEXPORT void JNICALL
Java_com_tunsafe_app_TunSafeService_jniStop(JNIEnv *env, jobject /*service*/) {
  pthread_mutex_lock(&g_backend_mutex);
  // Setting the exit flag wakes the poll loop.
  // NetworkBsd exposes exit_flag() for this purpose.
  // We don't have direct access here, so we just log — the caller should
  // close the tun fd or call jniStop from the same thread context.
  ALOGI("jniStop called");
  // TODO: expose NetworkBsd::RequestExit() via a public accessor if needed.
  pthread_mutex_unlock(&g_backend_mutex);
}

} // extern "C"

// ---------------------------------------------------------------------------
// Android-specific: hook outgoing TCP socket creation to call protect().
//
// TcpSocketBsd::InitializeOutgoing creates the socket fd in network_bsd.cpp.
// We need to protect it IMMEDIATELY after creation before connect() is called,
// otherwise the SYN packet goes through the VPN tunnel and loops.
//
// Solution: add a hook point in InitializeOutgoing. Since we can't easily
// modify network_bsd.cpp from here (it's compiled together), we add the
// protect call directly in network_bsd.cpp conditioned on OS_ANDROID,
// calling android_protect_socket() declared here as extern.
// ---------------------------------------------------------------------------
bool android_protect_socket_extern(int fd) {
  return android_protect_socket(fd);
}

#endif  // OS_ANDROID
