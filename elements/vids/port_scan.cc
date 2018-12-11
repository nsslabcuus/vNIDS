#include <click/config.h>
#include <click/logger.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/args.hh>

#include "port_scan.hh"

CLICK_DECLS

PortScan::PortScan()
    : _expiration_time(300), _record_head(NULL), _timer(this) {}
PortScan::~PortScan() {}

int PortScan::initialize(ErrorHandler*) {
  _timer.initialize(this);
  _timer.schedule_now();

  if (_record_head) {
    return 0;
  }

  _record_head = (portscan_record*)malloc(sizeof(portscan_record));
  if (!_record_head) return -1;

  _record_head->next = NULL;
  return 0;
}

int PortScan::configure(Vector<String>& conf, ErrorHandler* errh) {
  return Args(conf, this, errh).read("expire", _expiration_time).execute();
}

void PortScan::run_timer(Timer* timer) {
  assert(timer == &_timer);
  delete_timeout_record();

  // If no dns_records, reschedule a longer time
  if (!_record_head)
    _timer.reschedule_after_sec(_expiration_time * 2);
  else
    _timer.reschedule_after_sec(_expiration_time);
}

struct portscan_record* PortScan::is_Exist(uint64_t src_ip) {
  struct portscan_record* temp = _record_head->next;
  while (temp) {
    if (temp->src_ip == src_ip) {
      return temp;
    }

    temp = temp->next;
  }
  return NULL;
}
bool PortScan::add_record(uint32_t packet_size, uint32_t create_time,
                          uint64_t src_ip, uint64_t dst_ip, uint16_t dst_port) {
  struct portscan_record* temp =
      (struct portscan_record*)malloc(sizeof(struct portscan_record));

  if (!temp) {
    return false;
  }

  temp->src_ip = src_ip;
  temp->hostsize = 1;
  temp->portsize = 1;

  temp->hosts[0] = dst_ip;
  temp->ports[0] = dst_port;

  temp->last_time = create_time;
  temp->create_time = create_time;
  temp->packetcounter += 1;
  temp->packetsizecounter += packet_size;

  temp->next = _record_head->next;
  _record_head->next = temp;
  return true;
}

void PortScan::delete_timeout_record() {
  LOG_DEBUG("PortScan :: del_timeout_records");
  struct portscan_record *record = _record_head->next, *pre = _record_head;
  uint32_t expire_at = Timestamp::now().sec() - _expiration_time;
  while (record) {
    if (record->last_time > expire_at) {
      pre->next = record->next;
      free(record);
      record = pre->next;
    } else {
      pre = record;
      record = record->next;
    }
  }
}

void PortScan::update_record(struct portscan_record* record, uint64_t dst_ip,
                             uint16_t dst_port) {
  if (!record) {
    return;
  }
  if (record->hostsize > MAX_HOST || record->portsize > MAX_PORT) {
    return;
  }

  int i = 0;
  for (; i < record->hostsize; ++i) {
    if (record->hosts[i] == dst_ip) {
      break;
    }
  }
  if (i >= record->hostsize) {
    record->hosts[i] = dst_ip;
    record->hostsize++;
  }
  i = 0;
  for (; i < record->portsize; ++i) {
    if (record->ports[i] == dst_port) {
      break;
    }
  }
  if (i >= record->portsize) {
    record->ports[i] = dst_port;
    record->portsize++;
  }

  if (record->hostsize == MAX_HOST || record->portsize == MAX_PORT) {
    record->portsize++;
    record->hostsize++;
    // port scan candidate
    LOG_EVAL("Port Scan Attack! ip %llu hosts %d ports %d\n",
             (long long unsigned int)record->src_ip, record->hostsize,
             record->portsize);
  }
}

void PortScan::push(int port, Packet* p) {
  (void)port;
  // uint16_t src_port = -1,
  uint16_t dst_port = -1;
  const click_ip* ip = p->ip_header();
  uint64_t src_ip = (ip->ip_src).s_addr;
  uint64_t dst_ip = (ip->ip_dst).s_addr;

  if (IP_PROTO_TCP == ip->ip_p) {
    // src_port = ntohs(p->tcp_header()->th_sport);
    dst_port = ntohs(p->tcp_header()->th_dport);
  } else if (IP_PROTO_UDP == ip->ip_p) {
    // src_port = ntohs(p->udp_header()->uh_sport);
    dst_port = ntohs(p->udp_header()->uh_dport);
  }
  struct portscan_record* record = NULL;
  if ((record = is_Exist(src_ip)) != NULL) {
    record->last_time = Timestamp::now().sec();
    record->packetcounter += 1;
    record->packetsizecounter += ntohs(ip->ip_len);
    update_record(record, dst_ip, dst_port);
  } else {
    // add new record
    add_record(ntohs(ip->ip_len), (uint32_t)Timestamp::now().sec(), src_ip,
               dst_ip, dst_port);
  }
  output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PortScan)
ELEMENT_MT_SAFE(PortScan)
