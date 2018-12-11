#include <click/config.h>
#include <click/logger.h>
#include <clicknet/udp.h>
#include <click/args.hh>

#include "fake_dns_lw_detector.hh"
#include "packet_tags.hh"

CLICK_DECLS
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

void FAKE_DNS_LW_DETECTOR::push(int port, Packet *p) {
  UNUSED(port);
  // DNS tunnel detector only interested in dns request
  if (53 == ntohs(p->udp_header()->uh_dport)) {
    set_tag(p, PTAG_DNS_TUNNEL);
  }
  output(0).push(p);
}

FAKE_DNS_LW_DETECTOR::~FAKE_DNS_LW_DETECTOR() { LOGE(""); }

CLICK_ENDDECLS
EXPORT_ELEMENT(FAKE_DNS_LW_DETECTOR)
