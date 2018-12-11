#ifndef CLICK_VIDS_PERFLOWANALYSIS_HH
#define CLICK_VIDS_PERFLOWANALYSIS_HH

#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

typedef struct perflow_record {
  uint32_t src_ip;
  uint32_t dst_ip;

  uint16_t src_port;
  uint16_t dst_port;

  uint32_t last_time;
  uint32_t create_time;

  uint32_t packetcounter;
  uint32_t packetsizecounter;

  perflow_record* next;
} perflow_record;

class PerFlowAnalysis : public Element {
 public:
  PerFlowAnalysis();
  ~PerFlowAnalysis();

  const char* class_name() const { return "PerFlowAnalysis"; }
  const char* port_count() const { return PORTS_1_1; }

  int initialize(ErrorHandler*);
  int configure(Vector<String>& conf, ErrorHandler* errh);

  void run_timer(Timer*);
  virtual void push(int, Packet*);

 private:
  perflow_record* is_Exist(uint32_t, uint16_t, uint32_t, uint16_t);
  bool add_record(uint32_t, uint32_t, uint32_t, uint16_t, uint32_t, uint16_t);
  void delete_timeout_record();

  int32_t _expiration_time;
  perflow_record* _record_head;
  Timer _timer;
};

CLICK_ENDDECLS
#endif
