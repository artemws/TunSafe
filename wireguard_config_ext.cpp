// wireguard_config_ext.cpp
// Pre-processor wrapper for ParseWireGuardConfigFile/String that adds
// support for EndpointTCP = <addr>:<port> key in [Peer] sections.
//
// This file intercepts the config text, strips EndpointTCP lines,
// calls the original parser, then applies tcp_endpoint to each peer.
//
// Drop-in: just add this file to your build. It redefines
// ParseWireGuardConfigFile and ParseWireGuardConfigString via
// preprocessor macros defined in wireguard_config_ext.h.

#include "build_config.h"
// wireguard_config_ext.h intentionally NOT included here to avoid
// macro-redirecting our own ParseWireGuardConfigString calls.
#include "wireguard.h"
#include "wireguard_config.h"
#include "wireguard_proto.h"
#include "tunsafe_ipaddr.h"
#include "util.h"
#include <cstdio>

#include <string>
#include <vector>
#include <cstring>

// ---------------------------------------------------------------------------
// Extract EndpointTCP values from config text, remove those lines,
// return one entry per [Peer] section (empty string = no EndpointTCP).
// ---------------------------------------------------------------------------
static std::vector<std::string> StripEndpointTCP(std::string &config) {
  std::vector<std::string> tcp_eps;  // one per [Peer] section
  std::string out;
  out.reserve(config.size());

  bool in_peer = false;
  const char *p = config.c_str();

  while (*p) {
    const char *nl = strchr(p, '\n');
    size_t len = nl ? (size_t)(nl - p) : strlen(p);

    // Work on a trimmed copy of the line (no trailing \r\n)
    size_t tlen = len;
    while (tlen > 0 && (p[tlen-1] == '\r' || p[tlen-1] == ' ')) tlen--;

    char line[512] = {};
    if (tlen < sizeof(line) - 1) {
      memcpy(line, p, tlen);
    }

    if (line[0] == '[') {
      if (strncmp(line, "[Peer]", 6) == 0) {
        in_peer = true;
        tcp_eps.push_back("");  // placeholder for this peer
      } else {
        in_peer = false;
      }
      // Keep section headers
      out.append(p, len);
      if (nl) out += '\n';
    } else if (in_peer) {
      // Check for EndpointTCP key
      char *eq = strchr(line, '=');
      if (eq) {
        char *ke = eq - 1;
        while (ke > line && (*ke == ' ' || *ke == '\t')) ke--;
        char saved = *(ke+1);
        *(ke+1) = 0;

        // Trim value
        const char *val = eq + 1;
        while (*val == ' ' || *val == '\t') val++;

        if (strcmp(line, "EndpointTCP") == 0) {
          // Store the value, drop the line from output
          if (!tcp_eps.empty())
            tcp_eps.back() = val;
          // Skip appending this line
          *(ke+1) = saved;
          p = nl ? nl + 1 : p + len;
          continue;
        }
        *(ke+1) = saved;
      }
      out.append(p, len);
      if (nl) out += '\n';
    } else {
      out.append(p, len);
      if (nl) out += '\n';
    }

    p = nl ? nl + 1 : p + len;
  }

  config = std::move(out);
  return tcp_eps;
}

// ---------------------------------------------------------------------------
// Apply extracted EndpointTCP values to peers after parsing.
// ---------------------------------------------------------------------------
static void ApplyEndpointTCP(WireguardProcessor *wg,
                              const std::vector<std::string> &tcp_eps) {
  WgPeer *peer = wg->dev().first_peer();
  for (size_t i = 0; i < tcp_eps.size() && peer; i++, peer = peer->next_peer()) {
    if (tcp_eps[i].empty()) continue;
    const char *addr = tcp_eps[i].c_str();
    if (strncmp(addr, "tcp://", 6) == 0) addr += 6;
    IpAddr sin;
    if (ParseSockaddrInWithPort(addr, &sin, NULL)) {
      peer->SetTcpEndpoint(sin);
      RINFO("EndpointTCP applied: %s", addr);
    } else {
      RERROR("EndpointTCP: cannot parse '%s'", addr);
    }
  }
}

// ---------------------------------------------------------------------------
// Public API — these replace the originals via macros in wireguard_config_ext.h
// ---------------------------------------------------------------------------

bool ParseWireGuardConfigStringExt(WireguardProcessor *wg,
                                    const char *buf, size_t buf_size,
                                    DnsResolver *dns_resolver) {
  std::string config(buf, buf_size);
  std::vector<std::string> tcp_eps = StripEndpointTCP(config);
  if (!ParseWireGuardConfigString(wg, config.c_str(), config.size(), dns_resolver))
    return false;
  ApplyEndpointTCP(wg, tcp_eps);
  return true;
}

bool ParseWireGuardConfigFileExt(WireguardProcessor *wg,
                                  const char *filename,
                                  DnsResolver *dns_resolver) {
  std::string config;
  RINFO("Loading file: %s", filename);
  FILE *f = fopen(filename, "rb");
  if (!f) { RERROR("Unable to open: %s", filename); return false; }
  char buf_[4096];
  size_t n;
  while ((n = fread(buf_, 1, sizeof(buf_), f)) > 0)
    config.append(buf_, n);
  fclose(f);
  std::vector<std::string> tcp_eps = StripEndpointTCP(config);
  if (!ParseWireGuardConfigString(wg, config.c_str(), config.size(), dns_resolver))
    return false;
  ApplyEndpointTCP(wg, tcp_eps);
  return true;
}
