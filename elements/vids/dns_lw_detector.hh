#ifndef CLICK_VIDS_DNS_LW_DETECTOR_HH
#define CLICK_VIDS_DNS_LW_DETECTOR_HH
#include <click/element.hh>
#include <click/timer.hh>
CLICK_DECLS

class DNS_LW_DETECTOR : public Element {
 public:
  struct dns_record_t {
    uint32_t sip;
    int32_t create_time;
    uint32_t count;
    dns_record_t *next;
  };

  const char *port_count() const { return PORTS_1_1; }
  const char *class_name() const { return "DNS_LW_DETECTOR"; }

  DNS_LW_DETECTOR();
  ~DNS_LW_DETECTOR();

  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  /** @brief update record
   * @return true if need dpi
   */
  bool update_record(uint32_t);
  void del_timeout_records();

  void run_timer(Timer *);
  void push(int port, Packet *p);

 private:
  int32_t _expiration_time;
  uint32_t _count_threshold;
  uint32_t _payload_len_threshold;
  dns_record_t *dns_records;
  Timer _timer;
};

CLICK_ENDDECLS

#endif
