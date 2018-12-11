#ifndef CLICK_VIDS_DNSANALYZER_HH
#define CLICK_VIDS_DNSANALYZER_HH
#include "analyzer.hh"
#include "clicknet/dns.h"
CLICK_DECLS

class DNSAnalyzer : public Analyzer {
 public:
  ~DNSAnalyzer();
  const char *class_name() const { return "DNSAnalyzer"; }
  virtual void push(int port, Packet *p);

 private:
};

CLICK_ENDDECLS
#endif
