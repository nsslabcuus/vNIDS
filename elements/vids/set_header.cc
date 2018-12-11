/*
 * Set_Header -- check whether it is a kind of geneve packet, if it is, then set
 * the actual header
 */

#include <click/config.h>
#include <click/logger.h>
#include <clicknet/geneve.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>

#include "set_header.hh"

CLICK_DECLS

extern int geneve_opt_len;

SetHeader::SetHeader() {}

SetHeader::~SetHeader() {}

void SetHeader::push(int, Packet* p) {
  unsigned char* ctr = (unsigned char*)(p->data() + 12);

  if (*ctr == 0x65 && *(ctr + 1) == 0x58) {
    uint32_t size = 14 + sizeof(click_ip) + sizeof(click_udp) +
                    sizeof(click_geneve) + geneve_opt_len;

    click_ip* ipptr = (click_ip*)(p->data() + size + 14);

    uint32_t iplen = ipptr->ip_hl * 4;

    p->set_network_header((unsigned char*)(p->data() + size + 14), iplen);
  }

  output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SetHeader)
ELEMENT_MT_SAFE(SetHeader)
