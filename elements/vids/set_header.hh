#ifndef CLICK_SET_HEDER_HH
#define CLICK_SET_HEADER_HH

#include <click/element.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>
CLICK_DECLS

class SetHeader : public Element {
 public:
  SetHeader() CLICK_COLD;
  ~SetHeader() CLICK_COLD;

  const char *class_name() const { return "SetHeader"; }
  const char *port_count() const { return PORTS_1_1; }

  void push(int, Packet *);
};

CLICK_ENDDECLS
#endif
