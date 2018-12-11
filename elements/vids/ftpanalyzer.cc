#include <click/config.h>
#include <click/logger.h>
#include <clicknet/tcp.h>
extern "C" {
#include <string.h>
}

#include "event.hh"
#include "ftpanalyzer.hh"
#include "packet_tags.hh"

CLICK_DECLS
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

void FTPAnalyzer::push(int port, Packet* p) {
  /*
  if(!get_tag(p, PTAG_MLTSTP))
  {
      p->kill();
      return;
  }
  */
  const char* payload =
      (const char*)p->transport_header() + (p->tcp_header()->th_off << 2);
  UNUSED(payload);
  UNUSED(port);
  //(void)payload;
  // ftp data activity, may be ftp download or upload
  // if(payload[0] == 'P' && payload[1] == 'K')
  {
    LOG("FTP_DOWNLOAD_ZIP");
    event_t* event = alloc_event_data(0);
    event->event_type = FTP_DOWNLOAD_ZIP;
    event->fill_connect(p);
    send_event(event, p->timestamp_anno());
    dealloc_event(event);
    p->kill();
  }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(FTPAnalyzer)
