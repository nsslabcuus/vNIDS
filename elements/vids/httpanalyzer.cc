#include <click/config.h>
#include <click/logger.h>
#include <clicknet/http.h>
#include <clicknet/tcp.h>
#include "packet_tags.hh"
extern "C" {
#include <string.h>
}

#include "datamodel.hh"
#include "event.hh"
#include "httpanalyzer.hh"

CLICK_DECLS
void HTTPAnalyzer::push(int port, Packet *p) {
  (void)port;
  const unsigned char *payload = (const unsigned char *)p->transport_header() +
                                 (p->tcp_header()->th_off << 2);
  HttpHeaders headers;
  int error_flag = 0;

  if ('M' == *payload && 'Z' == *(payload + 1)) {
    LOG_DEBUG("HTTP_RESPONSE_EXE");
    event_t *event = alloc_event_data(0);
    event->event_type = HTTP_RESPONSE_EXE;
    event->fill_connect(p);
    send_event(event, p->timestamp_anno());
    dealloc_event(event);
    p->kill();
  }

#define BINPAC_HTTP_PARSER
#ifdef BINPAC_HTTP_PARSER
  binpac::init();
  binpac::HTTP::HTTP_Conn *interp;
  interp = new binpac::HTTP::HTTP_Conn(&headers);

  binpac::const_byteptr http_data = (unsigned char *)payload;
  binpac::const_byteptr http_data_end = (unsigned char *)p->end_data();
  bool real_orig = true;

  if ('H' == *payload && 'T' == *(payload + 1)) {
    real_orig = false;
  }

  try {
    interp->NewData(real_orig, http_data, http_data_end);
  }

  catch (const binpac::Exception &e) {
    error_flag = 1;
    LOGE("Binpac exception: HTTP parse failed, Binpac exception: %s",
         e.c_msg());
  }

#else
  if (http_parse(payload, p->end_data(), &headers)) {
    error_flag = 1;
    LOGE("HTTP parse failed, packets may invalid!");
  }

#endif
  if (error_flag == 0 && headers.size() > 0) {
    String cookie = headers.find("Cookie");
    String content_type = headers.find("Content-Type");
    if (content_type) {
      LOG_DEBUG("Content-Type: %s", content_type.c_str());
      if (strncmp(content_type.c_str(), "text/html", 9) == 0) {
        event_t *event = alloc_event_data(0);
        event->event_type = HTTP_RESPONSE_HTML;
        event->fill_connect(p);
        send_event(event, p->timestamp_anno());
        dealloc_event(event);
        p->kill();
      } else if (strncmp(content_type.c_str(), "application/octet-stream",
                         24) == 0 ||
                 strncmp(content_type.c_str(), "application/x-msdos-program",
                         27) == 0) {
        event_t *event = alloc_event_data(0);
        event->event_type = HTTP_RESPONSE_EXE;
        event->fill_connect(p);
        send_event(event, p->timestamp_anno());
        dealloc_event(event);
        p->kill();
      } else if (strncmp(content_type.c_str(), "application/zip", 15) == 0) {
        event_t *event = alloc_event_data(0);
        event->event_type = HTTP_RESPONSE_ZIP;
        event->fill_connect(p);
        send_event(event, p->timestamp_anno());
        dealloc_event(event);
        p->kill();
      }
    }

    if (cookie) {
      String useragent = headers.find("User-Agent");
      // If no useragent found in headers, fill in random integer
      if (!useragent) useragent = String(click_random());
      event_t *event = alloc_event_data(2, cookie.length(), useragent.length());
      event->event_type = HTTP_COOKIE_USERAGENT;
      event->fill_connect(p);
      event->get_writer()(cookie.length(), cookie.c_str())(useragent.length(),
                                                           useragent.c_str());
      LOG_DEBUG("save cookie: %s", cookie.c_str());
      LOG_DEBUG("save useragent: %s", useragent.c_str());
      send_event(event, p->timestamp_anno());
      dealloc_event(event);
    }
  }
  p->kill();
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HTTPAnalyzer)
