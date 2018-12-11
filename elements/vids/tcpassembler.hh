#ifndef CLICK_VIDS_TCPASSEMBLER__HH
#define CLICK_VIDS_TCPASSEMBLER__HH

#include <clicknet/tcp.h>
#include <click/bighashmap.hh>
#include <click/element.hh>
#include <click/ipflowid.hh>
#include <click/string.hh>
#include <click/timer.hh>

CLICK_DECLS

/*
 * This element was designed to handle segmented tcp flows.
 * if received packets without segmented flag, just push it;
 * otherwise saving it to buffer and with runtimer to find completed packets to
 * push. if a packet arrives at TCPAssembler, but it's sequence number is
 * smaller than that of the first packet on the linked list, the packet is
 * deleted. in this case, TCPBuffer assumes the packet is either a retransmit
 * (if SKIP is false) or the puller is no longer interested in it (if SKIP is
 * true).
 *
 * the first packet arrives at TCPAssembler gets to set the initial sequence
 * number. it is expected that this packet will be either a SYN or a SYN ACK
 * packet.
 */

struct SegmentedPacketNode {
  Packet* data;
  unsigned seqno;
  unsigned seqlen;

  struct SegmentedPacketNode *next, *prev;
};

struct TCPSegmentedPacketElt {
 public:
  TCPSegmentedPacketElt() : head(NULL) {}

  ~TCPSegmentedPacketElt() {
    SegmentedPacketNode* thead = head;
    while (thead) {
      struct SegmentedPacketNode* tmp = thead->next;
      delete thead;
      thead = tmp;
    }
  }

  bool insertp(Packet* p, unsigned& seq, unsigned& ack);
  uint32_t checkGap();  // return the length without a gap in the buffer

  bool isSYNorFin(Packet* p);

  struct SegmentedPacketNode* head;
  unsigned nextseq;
  IPAddress sip, dip;
  uint16_t sp, dp;

  bool needack = false;
  /*
   * you can add any states here for future development
   */
};

class TCPAssembler : public Element {
 public:
  TCPAssembler();
  ~TCPAssembler();

  const char* class_name() const { return "TCPAssembler"; }
  const char* port_count() const { return PORTS_1_1; }

  int initialize(ErrorHandler*);
  int configure(Vector<String>& conf, ErrorHandler* errh);

  void run_timer(Timer*);
  void handle_timeout_flows();

  void outpacket(int, TCPSegmentedPacketElt*);

  virtual void push(int, Packet*);

  static unsigned seqlen(Packet*);
  static unsigned seqno(Packet*);

 private:
  // search a flow from hashmap
  struct TCPSegmentedPacketElt* getFlowHeadNode(IPFlowID& flowId);

  // add new flow to flow table; returns false if key already exists, true
  // otherwise. entry is not added to table in the former case
  bool add_flow_data(IPFlowID& flowId, Packet* p,
                     TCPSegmentedPacketElt* elt);  // IPFlowID

  // remove flow from table; returns true if removed an entry, false otherwise
  bool remove_flow(IPFlowID& flowId);  // remove flow from buffer

  HashMap<IPFlowID, TCPSegmentedPacketElt*>*
      tcpSegmentedFlows;  // buffer for saving flow data
  HashMap<IPFlowID, uint64_t>*
      flowTimestamp;  // buffer for detecting expired flows

  uint32_t _max_segment_flows;  // max number of segment flows in hash map

  uint64_t _expiration_time;   // maximum exist time(ms), otherwise would be
                               // delete from buffer
  uint32_t _max_segment_data;  // the maximum data to output
  bool _skip;                  // same as parameters in element tcpbuffer

  Timer _timer;
};

inline bool TCPSegmentedPacketElt::insertp(Packet* p, unsigned& seqno,
                                           unsigned& seqlen) {
  if (seqlen == 0) {
    return false;
  }

  struct SegmentedPacketNode* node = new SegmentedPacketNode();

  if (node == NULL) {
    return false;
  }

  // printf("666\n");
  node->data = p;
  node->seqno = seqno;
  node->seqlen = seqlen;

  struct SegmentedPacketNode thead;
  thead.next = head;

  struct SegmentedPacketNode *tmp = head, *pre = &thead;

  // printf("seq %u len %u\n", seqno, seqlen);

  while (tmp != NULL) {
    if (seqno < tmp->seqno) {
      if (seqno + seqlen > tmp->seqno) {
        // overlap happens

        // printf ("packet overlaps!");

        delete node;
        return false;
      }
      break;
    }
    pre = tmp;
    tmp = tmp->next;
  }

  // printf("add sucessfully\n");
  tmp = pre->next;
  pre->next = node;
  node->next = tmp;

  head = thead.next;

  return true;
}

inline uint32_t TCPSegmentedPacketElt::checkGap() {
  if (head == NULL) {
    // printf("no packets");
    return 0;
  }

  // debug
  /*
  printf("Debug:\n");
  struct SegmentedPacketNode* tt = head;
  while (tt) {

      printf("len %lld  seq %lld\n", tt->seqlen, tt->seqno);
      tt = tt->next;
  }
  printf("Debug End!\n");
  */
  struct SegmentedPacketNode* tmp = head->next;

  int offset = isSYNorFin(head->data);

  int ret = head->seqlen;

  uint32_t sno = head->seqno + ret;
  while (tmp) {
    if (sno != tmp->seqno) {
      // printf("len %d  seq %d", len, tmp->seqno);
      break;
    }
    offset += isSYNorFin(tmp->data);
    ret += tmp->seqlen;
    sno += tmp->seqlen;
    tmp = tmp->next;
  }
  // printf("off %d\n", offset);
  return ret - offset;
}

inline bool TCPSegmentedPacketElt::isSYNorFin(Packet* p) {
  if (p == NULL) {
    return false;
  }
  const click_tcp* tcph =
      reinterpret_cast<const click_tcp*>(p->transport_header());

  if ((tcph->th_flags & TH_SYN) || (tcph->th_flags & TH_FIN)) {
    return true;
  }
  return false;
}

inline unsigned TCPAssembler::seqlen(Packet* p) {
  const click_ip* iph = p->ip_header();
  const click_tcp* tcph =
      reinterpret_cast<const click_tcp*>(p->transport_header());
  unsigned seqlen =
      (ntohs(iph->ip_len) - (iph->ip_hl << 2) - (tcph->th_off << 2));

  if ((tcph->th_flags & TH_SYN) || (tcph->th_flags & TH_FIN)) {
    seqlen++;
  }

  return seqlen;
}

inline unsigned TCPAssembler::seqno(Packet* p) {
  const click_tcp* tcph =
      reinterpret_cast<const click_tcp*>(p->transport_header());
  // printf("size %lld %lld\n", tcph->th_seq, ntohl(tcph->th_seq));
  return ntohl(tcph->th_seq);
}

CLICK_ENDDECLS
#endif
