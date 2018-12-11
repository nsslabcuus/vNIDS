#ifndef CLICK_VIDS_UDPCLASSIFIER_HH
#define CLICK_VIDS_UDPCLASSIFIER_HH
#include <click/logger.h>
#include <click/element.hh>
CLICK_DECLS

/** @class UDPClassifier
 * @details
 * UDP Packet do not need to assemble<br/>
 * Analyze UDP <br/>
 * output 1 to DNSAnalyzer
 */
class UDPClassifier : public Element {
 public:
  UDPClassifier() {}
  ~UDPClassifier();
  const char *port_count() const { return "1/1-"; }
  const char *class_name() const { return "UDPClassifier"; }
  virtual void push(int port, Packet *p);
};

CLICK_ENDDECLS

#endif
