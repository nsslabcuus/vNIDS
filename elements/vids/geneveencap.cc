#include <click/config.h>
#include <click/logger.h>
#include <clicknet/geneve.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/args.hh>
#include "geneveencap.hh"

CLICK_DECLS

/** @brief Used by lightweight detectors
 */
int geneve_opt_len = 16;

/*
 * Let the element be able to configure the dest mac address for the geneve
 * header
 */
int GeneveEncap::configure(Vector<String> &conf, ErrorHandler *errh) {
  int res = Args(conf, this, errh).read("opt_len", _opt_len).execute();
  if (0 == res) {
    if (_opt_len <= 0) _opt_len = 1;
    geneve_opt_len = _opt_len * 4;
  }
  return res;
}

/**@brief Add the Geneve Header but we only care about the Variable Options.
 */
Packet *GeneveEncap::simple_action(Packet *p_in) {
  uint32_t size = 14 + sizeof(click_udp) + sizeof(click_ip) +
                  sizeof(click_geneve) + _opt_len * 4;

  WritablePacket *p = p_in->push(size);
  // copy the ether header. @todo may need to fill the ip header
  memcpy(p->data(), p->data() + size,
         14 + sizeof(click_ip) + sizeof(click_udp));

  unsigned char *ctr = (unsigned char *)(p->data() + 12);
  *ctr = 0x65;
  *(ctr + 1) = 0x58;

  // modify ip data length
  click_ip *ptr = (click_ip *)(p->data() + 14);
  ptr->ip_len = htons(p->length() - 14);

  click_geneve *gh =
      (click_geneve *)(p->data() + 14 + sizeof(click_ip) + sizeof(click_udp));
  gh->opt_len = _opt_len;
  bzero(gh->opt, _opt_len * 4);
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GeneveEncap)
