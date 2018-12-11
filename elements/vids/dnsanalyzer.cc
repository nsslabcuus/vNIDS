#include <click/config.h>
#include <cstring>
#include "dnsanalyzer.hh"
#include "event.hh"
#include "datamodel.hh"
CLICK_DECLS

void DNSAnalyzer::push(int port, Packet* p) {
  (void)port;
  const click_dns* dns = p->dns_header();
  click_dns_info info;
  info.dh_ancount = 0;

#define BINPAC_DNS_PARSER
#ifdef BINPAC_DNS_PARSER
  binpac::DNS::DNS_Conn* interp;
  interp = new binpac::DNS::DNS_Conn(&info);

  binpac::const_byteptr dns_data = (unsigned char*)dns;
  bool real_orig = true;

  try {
    interp->NewData(real_orig, dns_data, dns_data + p->length());
  } catch (const binpac::Exception& e) {
    LOGE("DNS parse failed, Binpac exception: %s", e.c_msg());
    output(1).push(p);
  }

#else
  if (dns_parse_info((const unsigned char*)(dns + 1), p->end_data(), dns,
                     &info)) {
    // @todo May need to generate some events ?
    LOGE("DNS parse failed, packets may invalid!");
    output(1).push(p);
  }
#endif

  if (DNS_TYPE_A == info.dns_type && DNS_CLASS_IN == info.dns_class) {
    uint32_t q_len;
    if (info.qname)
      q_len = strlen(info.qname);
    else
      q_len = 0;

    event_t* event = alloc_event_data(2, sizeof(uint32_t), q_len);
    event->event_type = DNS_REQUEST;
    event->fill_connect(p);
    event_t::DataWriter writer = event->get_writer()(info.dns_record_ip);
    if (info.qname) writer(q_len, info.qname);

    LOG_DEBUG("Save state: dns info %u", info.dns_record_ip);
    LOG_DEBUG("Save state: dns qname %s", info.qname);
    send_event(event, p->timestamp_anno());

    dealloc_event(event);
    p->kill();
  } else {
    output(1).push(p);
  }
}

DNSAnalyzer::~DNSAnalyzer() {}
CLICK_ENDDECLS
EXPORT_ELEMENT(DNSAnalyzer)
