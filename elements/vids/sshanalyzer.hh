#ifndef CLICK_VIDS_SSHANALYZER_HH
#define CLICK_VIDS_SSHANALYZER_HH
#include "analyzer.hh"

CLICK_DECLS

class SSHAnalyzer : public Analyzer {
 public:
  const char *class_name() const { return "SSHAnalyzer"; }
  virtual void push(int port, Packet *p);
};

CLICK_ENDDECLS

#endif
