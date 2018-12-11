#ifndef CLICK_VIDS_FTPANALYZER_HH
#define CLICK_VIDS_FTPANALYZER_HH

#include "analyzer.hh"

CLICK_DECLS

class FTPAnalyzer : public Analyzer {
 public:
  const char* class_name() const { return "FTPAnalyzer"; }
  virtual void push(int, Packet*);
};

CLICK_ENDDECLS

#endif
