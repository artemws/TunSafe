#include "build_config.h"

// Signal that tunsafe_bsd.cpp is being included via amalgam (avoids duplicate definitions)
#define TUNSAFE_AMALGAM_INCLUDE 1
// Skip asm for IOS simulator
#if defined(OS_IOS) && defined(ARCH_CPU_X86_FAMILY)
#define CHACHA20_WITH_ASM 0
#define BLAKE2S_WITH_ASM 0
#endif

// Skip asm on arm64 android
#if defined(OS_ANDROID) && defined(ARCH_CPU_ARM64)
#define CHACHA20_WITH_ASM 0
#define BLAKE2S_WITH_ASM 0
#endif

#include "wireguard.cpp"
#include "wireguard_proto.cpp"
#include "wireguard_config.cpp"
#include "wireguard_config_ext.cpp"
#include "tunsafe_wg_plugin.cpp"
#include "util.cpp"
#include "tunsafe_threading.cpp"
#include "tunsafe_cpu.cpp"
#include "ip_to_peer_map.cpp"
#include "tunsafe_ipaddr.cpp"
#include "crypto/curve25519/curve25519-donna.cpp"
#include "crypto/chacha20poly1305.cpp"
#include "crypto/blake2s/blake2s.cpp"
#include "crypto/siphash/siphash.cpp"
#include "crypto/aesgcm/aesgcm.cpp"
#include "crypto/sha/sha1.cpp"
#include "network_common.cpp"

#if defined(WITH_NETWORK_BSD)
#include "network_bsd.cpp"
#include "tunsafe_bsd.cpp"
#if !defined(OS_ANDROID)
#include "ts.cpp"
#include "benchmark.cpp"
#endif  // !defined(OS_ANDROID)
#endif  // defined(WITH_NETWORK_BSD)

#if defined(OS_ANDROID) && defined(WITH_NETWORK_BSD)
#include "tunsafe_android.cpp"
#endif
