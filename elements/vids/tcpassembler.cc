#include <click/config.h>
#include <click/logger.h>
#include <clicknet/geneve.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/args.hh>

#include "tcpassembler.hh"

CLICK_DECLS

extern int geneve_opt_len;

TCPAssembler::TCPAssembler()
    : tcpSegmentedFlows(NULL),
      flowTimestamp(NULL),
      _max_segment_flows(128),
      _expiration_time(30),
      _max_segment_data(10240),
      _skip(false),
      _timer(this) {
  tcpSegmentedFlows = new HashMap<IPFlowID, TCPSegmentedPacketElt*>();
  flowTimestamp = new HashMap<IPFlowID, uint64_t>();
}

TCPAssembler::~TCPAssembler() {
  // needs to release memory
  typedef HashMap<IPFlowID, TCPSegmentedPacketElt*>::iterator FlowsIter;

  for (FlowsIter iter = tcpSegmentedFlows->begin();
       iter != tcpSegmentedFlows->end(); iter++) {
    TCPSegmentedPacketElt* flow = iter.value();
    if (flow != NULL) {
      delete flow;
    }
  }

  if (flowTimestamp != NULL) {
    delete flowTimestamp;
  }

  if (tcpSegmentedFlows != NULL) {
    delete tcpSegmentedFlows;
  }
}

int TCPAssembler::initialize(ErrorHandler*) {
  _timer.initialize(this);
  _timer.schedule_now();

  return 0;
}

int TCPAssembler::configure(Vector<String>& conf, ErrorHandler* errh) {
  int ret = Args(conf, this, errh)
                .read("maxflows", _max_segment_flows)
                .read("expire", _expiration_time)
                .read("maxdata", _max_segment_data)
                .read("skip", _skip)
                .execute();

  if (_max_segment_data <= 0 || _max_segment_data > 20480) {
    _max_segment_data = 10240;
  }

  if (_max_segment_flows <= 0 || _max_segment_flows > 256) {
    _max_segment_flows = 128;
  }

  if (_expiration_time <= 0 || _expiration_time > 20) {
    _expiration_time = 10;
  }
  return ret;
}

void TCPAssembler::handle_timeout_flows() {
  // traverse HashMap (flowtimestamp)
  // to find timeout flows

  // if skip, delete these flows
  // otherwise, output these flows

  typedef HashMap<IPFlowID, uint64_t>::iterator FlowsIter;

  uint64_t expire_at = Timestamp::now().sec() - _expiration_time;
  for (FlowsIter iter = flowTimestamp->begin(); iter != flowTimestamp->end();
       iter++) {
    IPFlowID flowid = iter.key();
    uint64_t time = iter.value();
    if (time < expire_at) {
      //
      //

      TCPSegmentedPacketElt* flow = tcpSegmentedFlows->find(flowid);
      if (!_skip) {
        // output the received packets

        outpacket(0, flow);
      } else {
        delete flow;
      }
      tcpSegmentedFlows->remove(flowid);
    }
  }
}

void TCPAssembler::run_timer(Timer* timer) {
  assert(timer == &_timer);
  handle_timeout_flows();
}

void TCPAssembler::outpacket(int port, TCPSegmentedPacketElt* elt) {
  // make a new packet and output it

  if (elt == NULL) {
    return;
  }

  uint32_t len = elt->checkGap();

  // if (len > 0) {

  struct SegmentedPacketNode* tmp = elt->head;

  Packet* p = tmp->data;

  click_tcp* ptcph = (click_tcp*)p->transport_header();
  uint32_t ptcph_size = ptcph->th_off * 4;

  uint32_t head_size =
      reinterpret_cast<const unsigned char*>(p->transport_header()) -
      reinterpret_cast<const unsigned char*>(p->data()) + ptcph_size;

  // LOGE("head size %u \n", head_size);
  uint32_t size = head_size + len;

  // LOGE("headsize %d size %d len %d\n", head_size, size, len);
  WritablePacket* q = Packet::make(size);

  // LOGE("packet length %d\n", q->length());
  memcpy(q->data(), p->data(), head_size);

  uint32_t cur = head_size;

  // printf("cur %d size %d\n", cur, size);

  while (cur < size) {
    Packet* tp = tmp->data;

    click_tcp* tp_tcph = (click_tcp*)tp->transport_header();
    uint32_t tcph_size = tp_tcph->th_off * 4;
    uint32_t clen = tmp->seqlen - elt->isSYNorFin(tp);
    // LOGE("clen %d", clen);
    if (clen > 0) {
      memcpy(q->data() + cur,
             reinterpret_cast<const unsigned char*>(tp->transport_header()) +
                 tcph_size,
             clen);
    }
    cur += clen;
    tmp = tmp->next;
    // printf("cur %d size %d\n", cur, size);
  }

  click_ip* ptr = (click_ip*)(q->data() + 14);
  ptr->ip_len = htons(q->length() - 14);

  ptr->ip_sum = 0;
  ptr->ip_sum = click_in_cksum((unsigned char*)ptr, ptr->ip_hl * 4);

  unsigned char* ctr = (unsigned char*)(p->data() + 12);

  if (*ctr == 0x65 && *(ctr + 1) == 0x58) {
    uint32_t geneve_size = 14 + sizeof(click_ip) + sizeof(click_udp) +
                           sizeof(click_geneve) + geneve_opt_len;

    click_ip* true_ip = (click_ip*)(q->data() + geneve_size + 14);

    // ip header len
    uint32_t iph_len = true_ip->ip_hl * 4;

    true_ip->ip_len = htons(len + sizeof(click_tcp) + iph_len);
    true_ip->ip_sum = 0;
    true_ip->ip_sum = click_in_cksum((unsigned char*)true_ip, iph_len);

    click_tcp* tcph = (click_tcp*)(q->data() + geneve_size + 14 + iph_len);

    // tcp length
    uint32_t tcplen = len + tcph->th_off * 4;
    unsigned csum = click_in_cksum((uint8_t*)tcph, tcplen);
    tcph->th_sum = click_in_cksum_pseudohdr(csum, true_ip, tcplen);

    // set header
    q->set_network_header((unsigned char*)true_ip, iph_len);
  } else {
    click_tcp* tcph = (click_tcp*)(q->data() + 14 + ptr->ip_hl * 4);

    // tcp length
    uint32_t tcplen = len + ptcph_size;
    unsigned csum = click_in_cksum((uint8_t*)tcph, tcplen);
    tcph->th_sum = click_in_cksum_pseudohdr(csum, ptr, tcplen);

    // set header
    q->set_network_header((unsigned char*)ptr, ptr->ip_hl * 4);
  }

  output(port).push(q);
  //}

  delete elt;
}

void TCPAssembler::push(int, Packet* p) {
  const click_ip* ip = p->ip_header();

  if (ip == NULL) {
    p->kill();
    return;
  }

  /*
   * if the protocol of the input packet is not TCP,
   * or the tcp packet is not a segmented part,
   * then just simple output it without do anything
   */
  if (IP_PROTO_TCP != ip->ip_p) {
    output(0).push(p);
    return;
  }

  const click_tcp* tcph =
      reinterpret_cast<const click_tcp*>(p->transport_header());

  if (tcph == NULL) {
    output(0).push(p);
    return;
  }

  IPAddress sip(ip->ip_src);
  IPAddress dip(ip->ip_dst);

  uint16_t src_port = tcph->th_sport;
  uint16_t dst_port = tcph->th_dport;

  IPFlowID flowid(sip, dip, src_port, dst_port);

  TCPSegmentedPacketElt* head = tcpSegmentedFlows->find(flowid);
  // LOGE("00000");
  if (head == NULL) {
    // LOGE("000001");
    head = new TCPSegmentedPacketElt;
    // LOGE("00000001");
    // LOGE("000003");
    tcpSegmentedFlows->insert(flowid, head);
  }
  // LOGE("1111");
  flowTimestamp->insert(flowid, Timestamp::now().sec());
  // FIN to output the flow immediately
  if (tcph->th_flags & (TH_FIN)) {
    add_flow_data(flowid, p, head);

    outpacket(0, head);

    remove_flow(flowid);
    p->kill();
    return;
  }
  // LOGE("222");
  if (add_flow_data(flowid, p, head)) {
    // added a new window successfully
  } else {
    // failed to add the new packets
    // then kill the packets;
    p->kill();
  }
  // LOGE("333");
}

TCPSegmentedPacketElt* TCPAssembler::getFlowHeadNode(IPFlowID& flowid) {
  return tcpSegmentedFlows->find(flowid);
}

bool TCPAssembler::add_flow_data(IPFlowID& flowId, Packet* p,
                                 TCPSegmentedPacketElt* elt) {
  if (elt == NULL) {
    return false;
  }

  uint32_t sno = seqno(p);
  uint32_t slen = seqlen(p);
  // LOGE("444");
  elt->insertp(p, sno, slen);

  elt->nextseq = sno + slen;
  elt->sip = flowId.saddr();
  elt->dip = flowId.daddr();
  elt->sp = flowId.sport();
  elt->dp = flowId.dport();
  // LOGE("555");

  return true;
}

bool TCPAssembler::remove_flow(IPFlowID& flowId) {
  return tcpSegmentedFlows->remove(flowId) && flowTimestamp->remove(flowId);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(TCPAssembler)
