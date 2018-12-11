#ifndef CLICK_VIDS_ANALYZER_HH
#define CLICK_VIDS_ANALYZER_HH
#include <click/logger.h>
#include <click/element.hh>
CLICK_DECLS

/** @file elements/vids/analyzer.hh
 * @brief Base class for analyzers
 */

struct event_t;

/** @class Analyzer
 * @brief base class for analyzers
 * @todo May be able to use configure string to classify the outputs port <br/>
 */

class Analyzer : public Element {
 public:
  /** @brief
   * At least one output
   */
  const char *port_count() const { return "1/1-"; }
  /** @brief
   * push function for Analyzer Elements <br/>
   */
  virtual void push(int port, Packet *p);
  const char *class_name() const { return "Analyzer"; }

 protected:
  virtual void send_event(event_t *, const Timestamp &);
};

CLICK_ENDDECLS
#endif
