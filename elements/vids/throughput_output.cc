#include <click/config.h>
#include <click/logger.h>
#include <click/args.hh>

#include <stdio.h>
#include <time.h>
#include "throughput_output.hh"

CLICK_DECLS

Throughput::Throughput()
    : _timer(this),
      pkt_cnts(0),
      pkt_sizes(0),
      allpkt_cnts(0),
      allpkt_sizes(0),
      output_interval(1),
      pos(0) {}

Throughput::~Throughput() {}

int Throughput::configure(Vector<String> &conf, ErrorHandler *errh) {
  return Args(conf, this, errh)
      .read("interval", output_interval)
      .read("pos", pos)
      .execute();
}

int Throughput::initialize(ErrorHandler *) {
  _timer.initialize(this);
  _timer.schedule_now();
  return 0;
}

void Throughput::update() {
  allpkt_cnts += pkt_cnts;
  allpkt_sizes += pkt_sizes;
  printf(
      "Postion %d, Packets Recived %d, Packets Sizes %d, All cnts %d, All "
      "sizes %d\n",
      pos, pkt_cnts, pkt_sizes, allpkt_cnts, allpkt_sizes);

  pkt_cnts = 0;
  pkt_sizes = 0;
}

void Throughput::run_timer(Timer *timer) {
  assert(timer == &_timer);
  update();
  _timer.reschedule_after_sec(output_interval);
}

void Throughput::push(int port, Packet *p) {
  if (p == NULL) return;
  pkt_cnts++;
  pkt_sizes += p->length();

  port = 0;
  output(port).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Throughput)
