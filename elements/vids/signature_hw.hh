#ifndef CLICK_VIDS_SIGNATUREDETECTOR_HH
#define CLICK_VIDS_SIGNATUREDETECTOR_HH

#include <click/element.hh>
#include <sstream>
#include <string>
#include <vector>

CLICK_DECLS

class SignatureDetector : public Element {
 public:
  SignatureDetector() CLICK_COLD;

  const char *class_name() const { return "SignatureDetector"; }
  const char *port_count() const { return PORTS_1_1; }

  int initialize(ErrorHandler *);

  Packet *simple_action(Packet *);

 private:
  std::vector<std::string> signatures;
  std::vector<std::vector<int>> nexts;

  void get_next(std::string &, std::vector<int> &);
  void get_nexts();
  bool compare(std::string &);
  bool compare(std::string &, std::string &, std::vector<int> &);
};

CLICK_ENDDECLS
#endif
