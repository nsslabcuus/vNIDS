#include <click/config.h>
#include <click/logger.h>
#include <clicknet/udp.h>
#include <click/args.hh>

#include "dns_lw_detector.hh"
#include "packet_tags.hh"

CLICK_DECLS
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

DNS_LW_DETECTOR::DNS_LW_DETECTOR()
    : _expiration_time(10),
      _count_threshold(10),
      _payload_len_threshold(100),
      dns_records(NULL),
      _timer(this) {}

int DNS_LW_DETECTOR::configure(Vector<String> &conf, ErrorHandler *errh) {
  return Args(conf, this, errh)
      .read("expire", _expiration_time)
      .read("threshold", _count_threshold)
      .read("max_len", _payload_len_threshold)
      .execute();
}

int DNS_LW_DETECTOR::initialize(ErrorHandler *) {
  _timer.initialize(this);
  _timer.schedule_now();
  return 0;
}

bool DNS_LW_DETECTOR::update_record(uint32_t sip) {
  dns_record_t *p = dns_records, *pre = NULL;
  while (NULL != p) {
    // Found
    if (sip == p->sip) {
      p->count++;
      if (p->count > _count_threshold) {
        if (NULL == pre)
          dns_records = p->next;
        else
          pre->next = p->next;
        LOG_EVAL("Suspicious DNS! query num %d > %d in %ds", p->count,
                 _count_threshold, _expiration_time);
        delete (p);
        return false;
      }
      return true;
    }
    pre = p;
    p = p->next;
  }
  // Create
  p = new dns_record_t;
  p->sip = sip;
  p->count = 1;
  p->create_time = Timestamp::now().sec();
  p->next = dns_records;
  dns_records = p;
  return true;
}

/** @brief Delete timeout records
 * @note This is based on that the linked list is sorted by decreased
 * create_time
 */
void DNS_LW_DETECTOR::del_timeout_records() {
  LOG_DEBUG("del_timeout_records");
  dns_record_t *record = dns_records, *pre = NULL;
  int32_t expire_at = Timestamp::now().sec() - _expiration_time;
  while (NULL != record && record->create_time > expire_at) {
    pre = record;
    record = record->next;
  }
  if (NULL == record) return;

  if (NULL != pre)
    pre->next = NULL;
  else
    dns_records = NULL;

  dns_record_t *tmp = record;
  while (NULL != record) {
    tmp = record;
    record = record->next;
    delete (tmp);
  }
}

void DNS_LW_DETECTOR::run_timer(Timer *timer) {
  assert(timer == &_timer);
  del_timeout_records();
  // If no dns_records, reschedule a longer time
  if (NULL == dns_records)
    _timer.reschedule_after_sec(_expiration_time * 2);
  else
    _timer.reschedule_after_sec(_expiration_time);
}

void DNS_LW_DETECTOR::push(int port, Packet *p) {
  // DNS tunnel detector only interested in dns request
  UNUSED(port);
  if (53 == ntohs(p->udp_header()->uh_dport)) {
    const click_ip *iph = p->ip_header();
    uint32_t sip = iph->ip_src.s_addr;
    // check payload length
    uint32_t payload_len =
        ntohs(iph->ip_len) - (iph->ip_hl << 2) - sizeof(click_udp);
    if (payload_len > _payload_len_threshold && update_record(sip)) {
      set_tag(p, PTAG_DNS_TUNNEL);
    }
  }
  output(0).push(p);
}

DNS_LW_DETECTOR::~DNS_LW_DETECTOR() {}

CLICK_ENDDECLS
EXPORT_ELEMENT(DNS_LW_DETECTOR)
