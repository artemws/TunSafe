// wireguard_config_ext.h
// Include this header to activate EndpointTCP support via pre-processing wrappers.
// It redirects ParseWireGuardConfigString/File to their *Ext counterparts which
// strip EndpointTCP lines before passing to the original parser, then apply
// tcp_endpoint to each peer afterwards.
//
// Usage: add #include "wireguard_config_ext.h" to any translation unit that
// calls ParseWireGuardConfigString or ParseWireGuardConfigFile, OR add it to
// a common header that is already included everywhere.
//
// Build: add wireguard_config_ext.cpp to your source list.

#ifndef WIREGUARD_CONFIG_EXT_H_
#define WIREGUARD_CONFIG_EXT_H_

#include <stddef.h>

class WireguardProcessor;
class DnsResolver;

bool ParseWireGuardConfigStringExt(WireguardProcessor *wg,
                                    const char *buf, size_t buf_size,
                                    DnsResolver *dns_resolver);

bool ParseWireGuardConfigFileExt(WireguardProcessor *wg,
                                  const char *filename,
                                  DnsResolver *dns_resolver);

// Redirect the originals to Ext versions everywhere this header is included.
#define ParseWireGuardConfigString  ParseWireGuardConfigStringExt
#define ParseWireGuardConfigFile    ParseWireGuardConfigFileExt

#endif  // WIREGUARD_CONFIG_EXT_H_
