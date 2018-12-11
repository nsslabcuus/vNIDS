#ifndef CLICK_VIDS_HTTPANALYZER_HH
#define CLICK_VIDS_HTTPANALYZER_HH
#include "analyzer.hh"
CLICK_DECLS

/** @file elements/vids/httpanalyzer.hh
 * @brief Analyze HTTP
 */

/** @class HTTPAnalyzer
 * @details
 * only output event to port 0 <br/>
 */
class HTTPAnalyzer : public Analyzer {
 public:
  const char *class_name() const { return "HTTPAnalyzer"; }
  virtual void push(int port, Packet *p);
};

CLICK_ENDDECLS
#endif
