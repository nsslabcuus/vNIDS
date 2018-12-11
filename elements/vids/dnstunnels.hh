#ifndef CLICK_DNSTUNNELS_HH
#define CLICK_DNSTUNNELS_HH

#include <click/element.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>
CLICK_DECLS

typedef struct dnstunnels_record {
  uint32_t host_ip;
  int count;
  uint32_t create_time;
  dnstunnels_record *next;
} dnstunnels_record;

#define DNSTUNNELS_EXPIRATION 100
#define COUNT_THRESHOLD 100
#define PERCENTAGE_OF_COUNT 2
#define DNSTUNNELS_QUERY_LEN_THRESHOLD 27
#define REQUEST_COUNT_THRESHOLD 100

class DNSTUNNELS : public Element {
  int _anno;
  dnstunnels_record *_record_head = NULL;

 public:
  DNSTUNNELS() CLICK_COLD;
  ~DNSTUNNELS() CLICK_COLD;

  const char *class_name() const { return "DNSTUNNELS"; }
  const char *port_count() const { return PORTS_1_1; }

  bool can_live_reconfigure() const { return true; }

  int configure(Vector<String> &conf, ErrorHandler *errh);
  dnstunnels_record *check_hostip_exist(uint32_t host_ip);
  bool add_record(uint32_t, uint32_t);
  bool delete_record(dnstunnels_record *);
  Packet *pull(int port);
};

CLICK_ENDDECLS
#endif
