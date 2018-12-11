#include <click/config.h>
#include <clicknet/tcp.h>
extern "C" {
#include <string.h>
}

#include <click/logger.h>
#include "event.hh"
#include "packet_tags.hh"
#include "sshanalyzer.hh"

CLICK_DECLS
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

static const char ssh_version[] = "SSH-2.0";
static const int version_size = strlen(ssh_version);

void SSHAnalyzer::push(int port, Packet* p) {
  if (!get_tag(p, PTAG_MLTSTP)) {
    p->kill();
    return;
  }
  (void)port;
  const unsigned char* payload =
      p->transport_header() + (p->tcp_header()->th_off << 2);
  int payload_size = p->end_data() - payload;
  UNUSED(payload);
  UNUSED(payload_size);
  // if the server replies the client the ssh protocol version
  if (/*payload_size >= version_size
           &&*/
      ntohs(p->tcp_header()->th_sport) == 22
      /*&& 0 == strncmp((const char*)payload, ssh_version, version_size)*/) {
    event_t* event = alloc_event_data(0);
    event->event_type = SSH_AUTH_ATTEMPED;
    event->fill_connect(p);
    send_event(event, p->timestamp_anno());
    dealloc_event(event);
  }
  p->kill();
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SSHAnalyzer)
