/*
Geneve: Generic Network Virtualization Encapsulation
https://tools.ietf.org/html/draft-ietf-nvo3-geneve-00#section-3.1
*/

#ifndef CLICK_VIDS_GENEVE_HH
#define CLICK_VIDS_GENEVE_HH

#include <click/element.hh>

CLICK_DECLS

/**
 * The GeneveEncap will add some room in headroom.
 */
class GeneveEncap : public Element {
 public:
  const char *class_name() const { return "GeneveEncap"; }
  const char *port_count() const { return PORTS_1_1; }

  int configure(Vector<String> &conf, ErrorHandler *errh);
  Packet *simple_action(Packet *);

 private:
  /** @brief the opt len field of Geneve header.
   */
  uint32_t _opt_len;
};

CLICK_ENDDECLS

#endif
