/*
1. Check tags and destroy packets without specific tag
2. Calculate the processing time
*/
#ifndef CLICK_VIDS_CHECKTAGS_HH
#define CLICK_VIDS_CHECKTAGS_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "packet_tags.hh"

CLICK_DECLS

class CheckTags : public Element {
 public:
  CheckTags();
  ~CheckTags();
  const char *port_count() const { return "1-/1-"; }
  const char *class_name() const { return "CheckTags"; }

  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);
  void run_timer(Timer *);

  void do_statistics();
  virtual Packet *simple_action(Packet *p);

 private:
  ptag_t _tag;
  uint64_t packet_count;  // Theses three are used in statistics
  uint64_t notag_or_total;
  uint64_t process_us;
  bool _is_last;  // Indicate if the CheckTags is at the end of pipeline
  uint32_t
      _stat_times;  // To indicate how many times we have called do_statistics
  Timer _timer;
};

CLICK_ENDDECLS

#endif
