#include <click/config.h>
#include <click/logger.h>

#include "analyzer.hh"
#include "event.hh"

CLICK_DECLS
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

void Analyzer::push(int port, Packet *p) {
  UNUSED(port);
  send_event(NULL, p->timestamp_anno());
}

void Analyzer::send_event(event_t *event, const Timestamp &ts) {
  WritablePacket *p = make_event_packet(event);
  if (NULL == p) {
    return;
  }
  // copy the timestamp anno
  p->set_timestamp_anno(ts);
  output(0).push(p);
  LOG_DEBUG("send_event: type(%u) len(%u) connect(%u:%u, %u:%u, %d)\n",
            event->event_type, event->event_len, event->connect.src_ip,
            event->connect.src_port, event->connect.dst_ip,
            event->connect.dst_port, event->connect.protocol);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Analyzer)
