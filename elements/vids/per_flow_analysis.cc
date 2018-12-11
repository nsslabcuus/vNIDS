#include <click/config.h>
#include <click/logger.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/args.hh>

#include "per_flow_analysis.hh"

CLICK_DECLS

PerFlowAnalysis::PerFlowAnalysis()
    : _expiration_time(300), _record_head(NULL), _timer(this) {}
PerFlowAnalysis::~PerFlowAnalysis() {}

int PerFlowAnalysis::initialize(ErrorHandler*) {
  _timer.initialize(this);
  _timer.schedule_now();
  return 0;
}

int PerFlowAnalysis::configure(Vector<String>& conf, ErrorHandler* errh) {
  return Args(conf, this, errh).read("expire", _expiration_time).execute();
}

void PerFlowAnalysis::run_timer(Timer* timer) {
  assert(timer == &_timer);
  delete_timeout_record();

  // If no dns_records, reschedule a longer time
  if (!_record_head)
    _timer.reschedule_after_sec(_expiration_time * 2);
  else
    _timer.reschedule_after_sec(_expiration_time);
}

perflow_record* PerFlowAnalysis::is_Exist(uint32_t src_ip, uint16_t src_port,
                                          uint32_t dst_ip, uint16_t dst_port) {
  perflow_record* temp = _record_head;
  while (temp) {
    if (temp->src_ip == src_ip && temp->src_port == src_port &&
        temp->dst_ip == dst_ip && temp->dst_port == dst_port) {
      return temp;
    }

    temp = temp->next;
  }

  return NULL;
}
bool PerFlowAnalysis::add_record(uint32_t packet_size, uint32_t create_time,
                                 uint32_t src_ip, uint16_t src_port,
                                 uint32_t dst_ip, uint16_t dst_port) {
  perflow_record* temp = (perflow_record*)malloc(sizeof(struct perflow_record));

  if (!temp) {
    return false;
  }

  temp->src_ip = src_ip;
  temp->src_port = src_port;
  temp->dst_ip = dst_ip;
  temp->dst_port = dst_port;

  temp->last_time = create_time;
  temp->create_time = create_time;
  temp->packetcounter += 1;
  temp->packetsizecounter += packet_size;

  if (_record_head == NULL) {
    _record_head = temp;
    temp->next = NULL;
    return true;
  }

  temp->next = _record_head->next;
  _record_head = temp;
  return true;
}

void PerFlowAnalysis::delete_timeout_record() {
  LOG_DEBUG("del_timeout_records");
  perflow_record *record = _record_head, *pre = NULL;
  uint32_t expire_at = Timestamp::now().sec() - _expiration_time;
  while (record && record->last_time > expire_at) {
    pre = record;
    record = record->next;
  }
  if (!record) return;

  if (!pre)
    pre->next = NULL;
  else
    _record_head = NULL;

  perflow_record* tmp = record;
  while (NULL != record) {
    tmp = record;
    record = record->next;
    free(tmp);
  }
}
void PerFlowAnalysis::push(int port, Packet* p) {
  (void)port;
  uint16_t src_port = -1, dst_port = -1;
  const click_ip* ip = p->ip_header();
  uint32_t src_ip = (ip->ip_src).s_addr;
  uint32_t dst_ip = (ip->ip_dst).s_addr;

  if (IP_PROTO_TCP == ip->ip_p) {
    src_port = ntohs(p->tcp_header()->th_sport);
    dst_port = ntohs(p->tcp_header()->th_dport);
  } else if (IP_PROTO_UDP == ip->ip_p) {
    src_port = ntohs(p->udp_header()->uh_sport);
    dst_port = ntohs(p->udp_header()->uh_dport);
  }

  perflow_record* record = NULL;
  if ((record = is_Exist(src_ip, src_port, dst_ip, dst_port)) != NULL) {
    record->last_time = Timestamp::now().sec();
    record->packetcounter += 1;
    record->packetsizecounter += ntohs(ip->ip_len);
  } else {
    // add new record
    add_record(ntohs(ip->ip_len), (uint32_t)Timestamp::now().sec(), src_ip,
               src_port, dst_ip, dst_port);
  }

  output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PerFlowAnalysis)
ELEMENT_MT_SAFE(PerFlowAnalysis)
