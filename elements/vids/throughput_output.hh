#ifndef CLICK_VIDS_THROUGHPUT_OUTOUT_HH
#define CLICK_VIDS_THROUGHPUT_OUTPUT_HH

#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

class Throughput : public Element {
 public:
  const char *port_count() const { return PORTS_1_1; }
  const char *class_name() const { return "THROUPUT"; }

  Throughput();
  ~Throughput();

  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  void update();
  void run_timer(Timer *);
  void push(int port, Packet *p);

 private:
  Timer _timer;
  int pkt_cnts;
  int pkt_sizes;
  int allpkt_cnts;
  int allpkt_sizes;

  uint32_t output_interval;
  int pos;
};

CLICK_ENDDECLS

#endif
