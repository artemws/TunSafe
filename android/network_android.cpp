// SPDX-License-Identifier: AGPL-1.0-only
// TunSafe Android JNI bridge.
//
// Собирается только для Android через android/CMakeLists.txt.
// Не используется в Linux/macOS/Windows сборках.
//
// Архитектура:
//   Java VpnService  ──JNI──►  network_android.cpp
//                                    │
//                                    ▼
//                          AndroidBackend
//                          (subclass of TunsafeBackendBsd)
//                                    │
//                         ┌──────────┴───────────┐
//                         ▼                       ▼
//                  network_bsd.cpp          network_common.cpp
//            (TCP/UDP/poll/deferred close)  (TLS obfuscation:
//                                           fake records, padding,
//                                           HTTP/2 keepalive, SNI)

#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <string>
#include <vector>

#include "wireguard.h"
#include "wireguard_config.h"
#include "network_bsd.h"
#include "tunsafe_bsd.h"
#include "util.h"
#include "netapi.h"

#define LOG_TAG "TunSafe"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// protect() callback — вызывается из C++ чтобы исключить сокет из VPN туннеля
// ─────────────────────────────────────────────────────────────────────────────
static JavaVM     *g_jvm             = nullptr;
static jobject     g_vpn_service_obj = nullptr;
static jmethodID   g_protect_method  = nullptr;

static bool android_protect_socket(int fd) {
  if (!g_jvm || !g_vpn_service_obj || !g_protect_method)
    return false;

  JNIEnv *env   = nullptr;
  bool attached = false;
  int  ret      = g_jvm->GetEnv((void **)&env, JNI_VERSION_1_6);
  if (ret == JNI_EDETACHED) {
    if (g_jvm->AttachCurrentThread(&env, nullptr) != 0) return false;
    attached = true;
  } else if (ret != JNI_OK) {
    return false;
  }
  jboolean ok = env->CallBooleanMethod(g_vpn_service_obj, g_protect_method, (jint)fd);
  if (attached) g_jvm->DetachCurrentThread();
  return ok == JNI_TRUE;
}

// Вызывается из network_bsd.cpp при создании нового исходящего TCP сокета
bool android_protect_socket_extern(int fd) {
  return android_protect_socket(fd);
}

// ─────────────────────────────────────────────────────────────────────────────
// AndroidBackend
// ─────────────────────────────────────────────────────────────────────────────
class AndroidBackend
    : public TunsafeBackendBsd,
      public NetworkBsd::NetworkBsdDelegate,
      public ProcessorDelegate {
public:
  explicit AndroidBackend(int tun_fd);
  ~AndroidBackend() override;

  void RunLoop();

  // TunInterface
  void WriteTunPacket(Packet *packet) override;

  // UdpInterface
  bool Configure(int listen_port_udp, int listen_port_tcp) override;
  void WriteUdpPacket(Packet *packet) override;
  void CloseOutgoingTcpForAddr(const IpAddr &addr) override;

  // NetworkBsdDelegate
  void OnSecondLoop(uint64 now) override;
  void RunAllMainThreadScheduled() override;

  // ProcessorDelegate
  void OnConnected(WgPeer *peer) override;
  void OnConnectionRetry(WgPeer *peer, uint32 attempts) override;

  WireguardProcessor *processor() { return &processor_; }

protected:
  bool InitializeTun(char devname[16]) override;

private:
  void CloseOrphanTcpConnections();

  int                  tun_fd_;
  bool                 is_connected_;
  uint8                close_orphan_counter_;
  WireguardProcessor   processor_;
  NetworkBsd           network_;
  TunSocketBsd         tun_;
  UdpSocketBsd         udp_;
  TcpSocketListenerBsd tcp_listener_;
};

AndroidBackend::AndroidBackend(int tun_fd)
    : tun_fd_(tun_fd),
      is_connected_(false),
      close_orphan_counter_(0),
      processor_(this, this, this),
      network_(this, 1000),
      tun_(&network_, &processor_),
      udp_(&network_, &processor_),
      tcp_listener_(&network_, &processor_) {
  // Plugin не используется (нет CreateTunsafePlugin в NDK сборке)
  processor_.dev().SetPlugin(nullptr);
}

AndroidBackend::~AndroidBackend() {}

bool AndroidBackend::InitializeTun(char devname[16]) {
  snprintf(devname, 16, "tun0");
  if (!tun_.Initialize(tun_fd_)) {
    ALOGE("TunSocketBsd::Initialize failed for fd %d", tun_fd_);
    return false;
  }
  tun_fd_ = -1;   // TunSocketBsd теперь владеет fd
  return true;
}

void AndroidBackend::WriteTunPacket(Packet *packet) {
  tun_.WritePacket(packet);
}

bool AndroidBackend::Configure(int listen_port_udp, int listen_port_tcp) {
  if (!udp_.Initialize(listen_port_udp))
    return false;
  android_protect_socket(udp_.GetFd());

  if (listen_port_tcp != 0) {
    if (!tcp_listener_.Initialize(listen_port_tcp))
      return false;
    android_protect_socket(tcp_listener_.GetFd());
  }
  return true;
}

void AndroidBackend::WriteUdpPacket(Packet *packet) {
  if (packet->protocol & kPacketProtocolTcp)
    TcpSocketBsd::WriteTcpPacket(&network_, &processor_, packet);
  else
    udp_.WritePacket(packet);
}

void AndroidBackend::CloseOutgoingTcpForAddr(const IpAddr &addr) {
  char buf[kSizeOfAddress];
  for (TcpSocketBsd *tcp = network_.tcp_sockets(); tcp; tcp = tcp->next()) {
    if (tcp->endpoint_protocol() == kPacketProtocolTcp &&
        CompareIpAddr(&tcp->endpoint(), &addr) == 0) {
      uint8 rnd; OsGetRandomBytes(&rnd, 1);
      uint32 delay = 2 + (rnd % 7);   // 2–8 сек deferred close
      tcp->SetDeferredClose((uint32)(OsGetMilliseconds() / 1000) + delay);
      ALOGI("hybrid_tcp: TCP to %s closes in %us", PrintIpAddr(addr, buf), delay);
      return;
    }
  }
}

void AndroidBackend::OnSecondLoop(uint64 now) {
  if (!(close_orphan_counter_++ & 0xF))
    CloseOrphanTcpConnections();
  processor_.SecondLoop();
}

void AndroidBackend::RunAllMainThreadScheduled() {
  processor_.RunAllMainThreadScheduled();
}

void AndroidBackend::OnConnected(WgPeer *peer) {
  char buf[kSizeOfAddress], peer_buf[kSizeOfAddress];
  const char *peer_str = "(unknown)";
  if (peer) {
    const IpAddr &ep = peer->endpoint();
    if (ep.sin.sin_family != 0) peer_str = PrintIpAddr(ep, peer_buf);
  }
  if (!is_connected_) {
    const WgCidrAddr *a4 = nullptr;
    for (const WgCidrAddr &x : processor_.addr())
      if (x.size == 32) { a4 = &x; break; }
    uint32 ip = a4 ? ReadBE32(a4->addr) : 0;
    ALOGI("Connected. IP %s peer %s",
          ip ? print_ip(buf, ip) : "(none)", peer_str);
    is_connected_ = true;
  }
}

void AndroidBackend::OnConnectionRetry(WgPeer *peer, uint32 attempts) {
  if (attempts == 4) ALOGI("Connecting...");
}

void AndroidBackend::CloseOrphanTcpConnections() {
  std::vector<IpAddr> active;
  for (WgPeer *p = processor_.dev().first_peer(); p; p = p->next_peer())
    if (p->endpoint_protocol() & kPacketProtocolTcp)
      active.push_back(p->endpoint());

  for (TcpSocketBsd *tcp = network_.tcp_sockets(); tcp; tcp = tcp->next()) {
    if (tcp->endpoint_protocol() & kPacketProtocolIncomingConnection) continue;
    bool found = false;
    for (const IpAddr &ep : active)
      if (CompareIpAddr(&tcp->endpoint(), &ep) == 0) { found = true; break; }
    if (!found) {
      char buf[kSizeOfAddress];
      ALOGI("Closing orphan TCP to %s", PrintIpAddr(tcp->endpoint(), buf));
      tcp->SetDeferredClose((uint32)(OsGetMilliseconds() / 1000));
    }
  }
}

void AndroidBackend::RunLoop() {
  network_.RunLoop(nullptr);
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI
// ─────────────────────────────────────────────────────────────────────────────
static AndroidBackend  *g_backend       = nullptr;
static pthread_mutex_t  g_backend_mutex = PTHREAD_MUTEX_INITIALIZER;

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
  g_jvm = vm;
  return JNI_VERSION_1_6;
}

// void TunSafeService.jniStart(FileDescriptor tunFd, String config)
// Блокирует до конца VPN сессии — вызывать из фонового потока.
JNIEXPORT void JNICALL
Java_com_tunsafe_app_TunSafeService_jniStart(
    JNIEnv *env, jobject service, jobject tun_fd_obj, jstring config_jstr) {

  // Получаем raw fd из Java FileDescriptor
  jclass    fd_cls   = env->FindClass("java/io/FileDescriptor");
  jfieldID  fd_field = env->GetFieldID(fd_cls, "descriptor", "I");
  int tun_fd = env->GetIntField(tun_fd_obj, fd_field);
  if (tun_fd < 0) { ALOGE("jniStart: invalid tun fd"); return; }

  tun_fd = dup(tun_fd);
  if (tun_fd < 0) { ALOGE("jniStart: dup failed: %s", strerror(errno)); return; }
  fcntl(tun_fd, F_SETFD, FD_CLOEXEC);

  // Сохраняем VpnService для protect()
  jclass   svc_cls = env->GetObjectClass(service);
  g_protect_method  = env->GetMethodID(svc_cls, "protect", "(I)Z");
  g_vpn_service_obj = env->NewGlobalRef(service);

  const char *cfg_c = env->GetStringUTFChars(config_jstr, nullptr);
  std::string config(cfg_c ? cfg_c : "");
  env->ReleaseStringUTFChars(config_jstr, cfg_c);

  pthread_mutex_lock(&g_backend_mutex);
  if (g_backend) {
    ALOGE("jniStart: already running");
    pthread_mutex_unlock(&g_backend_mutex);
    close(tun_fd);
    return;
  }
  g_backend = new AndroidBackend(tun_fd);
  pthread_mutex_unlock(&g_backend_mutex);

  WireguardProcessor *proc = g_backend->processor();

  if (!ParseWireGuardConfigString(proc, config.c_str(), config.size(), nullptr)) {
    ALOGE("jniStart: config parse failed");
    goto cleanup;
  }

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
  g_backend = nullptr;
  pthread_mutex_unlock(&g_backend_mutex);

  env->DeleteGlobalRef(g_vpn_service_obj);
  g_vpn_service_obj = nullptr;
  g_protect_method  = nullptr;
}

// void TunSafeService.jniStop()
JNIEXPORT void JNICALL
Java_com_tunsafe_app_TunSafeService_jniStop(JNIEnv *, jobject) {
  ALOGI("jniStop called");
  // NetworkBsd::RunLoop проверяет exit_flag — можно добавить публичный метод
  // если нужна немедленная остановка. Сейчас выход через закрытие tun fd.
}

} // extern "C"
