#ifndef CLICK_VIDS_TCPCLASSIFIER_HH
#define CLICK_VIDS_TCPCLASSIFIER_HH
#include <click/element.hh>
CLICK_DECLS
/** @brief classify tcp payload <br/>
 * by port <br/>
 * by payload <br/>
 * determine if need to reassemble tcp packets <br/>
 */
class TCPClassifier : public Element {
 public:
  TCPClassifier();
  const char *port_count() const { return "1/1-"; }
  const char *class_name() const { return "TCPClassifier"; }
  int configure(Vector<String> &conf, ErrorHandler *errh);
  virtual void push(int port, Packet *p);

 private:
  Packet *reassemble(Packet *p);
  void classify(Packet *p);
};

CLICK_ENDDECLS
#endif
