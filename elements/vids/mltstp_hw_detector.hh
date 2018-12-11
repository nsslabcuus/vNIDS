#ifndef CLICK_MLTSTP_HW_DETECTOR_HH
#define CLICK_MLTSTP_HW_DETECTOR_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

typedef struct mltstp_hw_records {
  uint32_t ip;
  uint32_t steps;
  int32_t create_time;
  mltstp_hw_records *next;
} mltstp_hw_records;

#define MLTSTP_HW_EXPIRATION 3600

class MLTSTP_HW_DETECTOR : public Element {
  int _anno;
  mltstp_hw_records *_record_head = NULL;

 public:
  MLTSTP_HW_DETECTOR() CLICK_COLD;
  ~MLTSTP_HW_DETECTOR() CLICK_COLD;

  const char *class_name() const { return "MLTSTP_HW_DETECTOR"; }
  const char *port_count() const { return PORTS_1_1; }

  bool can_live_reconfigure() const { return true; }

  int initialize(ErrorHandler *errh);
  mltstp_hw_records *check_record_exist(uint32_t);
  bool add_record(uint32_t, uint32_t, uint32_t);
  bool delete_record(mltstp_hw_records *);
  // Packet *pull(int);
  Packet *simple_action(Packet *p);
};

CLICK_ENDDECLS
#endif
