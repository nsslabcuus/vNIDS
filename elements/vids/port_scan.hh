#ifndef CLICK_VIDS_PORTSCAN_HH
#define CLICK_VIDS_PORTSCAN_HH

#include <click/element.hh>
#include <click/timer.hh>

#define MAX_HOST 25
#define MAX_PORT 15

CLICK_DECLS

struct portscan_record {
  uint64_t src_ip;

  uint16_t portsize;
  uint16_t hostsize;

  uint32_t last_time;
  uint32_t create_time;

  uint64_t hosts[MAX_HOST + 10];
  uint16_t ports[MAX_PORT + 10];

  uint32_t packetcounter;
  uint32_t packetsizecounter;

  struct portscan_record* next;
};

class PortScan : public Element {
 public:
  PortScan();
  ~PortScan();

  const char* class_name() const { return "PortScan"; }
  const char* port_count() const { return PORTS_1_1; }

  int initialize(ErrorHandler*);
  int configure(Vector<String>& conf, ErrorHandler* errh);

  void run_timer(Timer*);
  virtual void push(int, Packet*);

 private:
  struct portscan_record* is_Exist(uint64_t);
  void update_record(struct portscan_record* record, uint64_t, uint16_t);
  bool add_record(uint32_t, uint32_t, uint64_t, uint64_t, uint16_t);
  void delete_timeout_record();

  int32_t _expiration_time;
  struct portscan_record* _record_head;
  Timer _timer;
};

CLICK_ENDDECLS
#endif
