#ifndef CLICK_DNS_HW_DETECTOR_HH
#define CLICK_DNS_HW_DETECTOR_HH

#include <click/element.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>
CLICK_DECLS

#define PERCENTAGE_OF_COUNT 2
#define QUERY_LEN_THRESHOLD 52

class DNS_HW_DETECTOR : public Element {
  int _anno;

 public:
  DNS_HW_DETECTOR() CLICK_COLD;
  ~DNS_HW_DETECTOR() CLICK_COLD;

  const char *class_name() const { return "DNS_HW_DETECTOR"; }
  const char *port_count() const { return PORTS_1_1; }

  bool can_live_reconfigure() const { return true; }

  int configure(Vector<String> &conf, ErrorHandler *errh);
  Packet *simple_action(Packet *);
};

CLICK_ENDDECLS
#endif
