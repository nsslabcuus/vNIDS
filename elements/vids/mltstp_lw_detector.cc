#include <click/config.h>
#include <click/logger.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <click/args.hh>

#include "mltstp_lw_detector.hh"
#include "packet_tags.hh"

CLICK_DECLS

int MLTSTP_LW_DETECTOR::initialize(ErrorHandler *) {
  _timer.initialize(this);
  _timer.schedule_now();
  return 0;
}

int MLTSTP_LW_DETECTOR::configure(Vector<String> &conf, ErrorHandler *errh) {
  return Args(conf, this, errh).read("expire", _expiration_time).execute();
}

void MLTSTP_LW_DETECTOR::run_timer(Timer *timer) {
  assert(timer == &_timer);
  if (NULL != stp_head) {
    int32_t expire_at = Timestamp::now().sec() - _expiration_time;
    mltstp_records_t *tmp = NULL;
    while (NULL != stp_head && stp_head->create_time < expire_at) {
      tmp = stp_head;
      stp_head = stp_head->next;
      stp_records.erase(tmp->host_ip);
      free(tmp);
    }
    if (NULL == stp_head) stp_tail = NULL;
    _timer.reschedule_after_sec(_expiration_time);
  } else {
    _timer.reschedule_after_sec(_expiration_time * 2);
  }
}

void MLTSTP_LW_DETECTOR::push(int port, Packet *p) {
  uint32_t host_ip = 0;
  const click_ip *ip_header = p->ip_header();
  const click_tcp *tcp_header = p->tcp_header();
  _step_t possible_step;
  switch (port) {
    case 0:  // http download, extract the ip_dst
      if (ntohs(tcp_header->th_dport) != 80) return output(port).push(p);
      host_ip = ip_header->ip_src.s_addr;
      possible_step = STP_HTTP_DOWNLOAD;
      break;
    case 1:  // ftp upload, extract the ip_src
      if (ntohs(tcp_header->th_dport) != 20) return output(port).push(p);
      host_ip = ip_header->ip_src.s_addr;
      possible_step = STP_FTP_UPLOAD;
      break;
    case 2:  // ssh login, extract the ip_src. Since we think a ssh-key-exchange
             // msg from server indicates a ssh login attempt
      if (ntohs(tcp_header->th_sport) != 22) return output(port).push(p);
      host_ip = ip_header->ip_src.s_addr;
      possible_step = STP_SSH;
      break;
    default:
      LOG_ERROR("port imposssible");
      p->kill();
      return;
  }
  mltstp_records_t *record = stp_records.find(host_ip);
  if (NULL == record) {
    if (STP_SSH == possible_step) {
      record = (mltstp_records_t *)malloc(sizeof(mltstp_records_t));
      record->host_ip = host_ip;
      record->create_time = Timestamp::now().sec();
      record->step = STP_NONE;
      record->next = NULL;
      stp_records.insert(host_ip, record);
      if (NULL == stp_head) {
        stp_tail = stp_head = record;
      } else {
        stp_tail->next = record;
        stp_tail = record;
      }
    } else  // if first packet is not ssh login, do not set PTAG_MLTSTP
      // output port is the same as the input port
      return output(port).push(p);
  }
  if (possible_step <= record->step + 1) {
    set_tag(p, PTAG_MLTSTP);
    if (possible_step == record->step + 1) {
      record->step = possible_step;
    }
  }
  output(port).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MLTSTP_LW_DETECTOR)
