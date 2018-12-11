#ifndef CLICK_VIDS_MULTISTEP_LW_DETECTOR_HH
#define CLICK_VIDS_MULTISTEP_LW_DETECTOR_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include <click/timer.hh>

CLICK_DECLS

class MLTSTP_LW_DETECTOR : public Element {
 public:
  enum _step_t { STP_NONE, STP_SSH, STP_HTTP_DOWNLOAD, STP_FTP_UPLOAD };
  struct mltstp_records_t {
    uint32_t host_ip;
    int32_t create_time;
    _step_t step;
    mltstp_records_t *next;
  };

  const char *port_count() const { return "3/3"; }
  const char *class_name() const { return "MLTSTP_LW_DETECTOR"; }

  MLTSTP_LW_DETECTOR()
      : _expiration_time(600), stp_head(NULL), stp_tail(NULL), _timer(this) {}
  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  void run_timer(Timer *);
  void push(int port, Packet *p);

 private:
  int32_t _expiration_time;
  HashMap<uint32_t, mltstp_records_t *> stp_records;
  // Add new record at the stp_tail,
  // so that we can delete the expired records from the stp_head easily.
  mltstp_records_t *stp_head;
  mltstp_records_t *stp_tail;
  Timer _timer;
};

CLICK_ENDDECLS
#endif
