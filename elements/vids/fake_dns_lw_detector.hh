#ifndef CLICK_VIDS_FAKE_DNS_LW_DETECTOR_HH
#define CLICK_VIDS_FAKE_DNS_LW_DETECTOR_HH
#include <click/element.hh>

CLICK_DECLS

class FAKE_DNS_LW_DETECTOR : public Element {
 public:
  ~FAKE_DNS_LW_DETECTOR();

  const char *port_count() const { return PORTS_1_1; }
  const char *class_name() const { return "FAKE_DNS_LW_DETECTOR"; }
  void push(int port, Packet *p);

 private:
};

CLICK_ENDDECLS
#endif
