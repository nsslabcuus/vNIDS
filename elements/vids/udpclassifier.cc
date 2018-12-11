
#include <click/config.h>
#include <clicknet/dns.h>
#include <clicknet/udp.h>
#include "udpclassifier.hh"

CLICK_DECLS

void UDPClassifier::push(int port, Packet* p) {
#define UDP_OUT_PORT 0
  (void)port;
  const click_udp* udp = p->udp_header();
  uint16_t uh_sport = ntohs(udp->uh_sport);
  uint16_t uh_dport = ntohs(udp->uh_dport);

  // LOGE("From %u: %d to %u: %d", p->ip_header()->ip_src.s_addr, uh_sport,
  // p->ip_header()->ip_dst.s_addr, uh_dport);
  if (53 == uh_sport || 53 == uh_dport) {
    output(UDP_OUT_PORT).push(p);
  } else {
    p->kill();
  }
}

UDPClassifier::~UDPClassifier() {}

CLICK_ENDDECLS
EXPORT_ELEMENT(UDPClassifier)
