#ifndef CLICK_SIDEJACKING_HH
#define CLICK_SIDEJACKING_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

typedef struct sidejacking_record {
  uint32_t ip;
  char* user_agent;
  char* cookie;
  sidejacking_record* next;
} sidejacking_record;

#define PROTOCOL_SSH 2222
#define PROTOCOL_IRC 6697
#define DHCP_CONTEXT_AVALIABLE 0

class SIDEJACKING : public Element {
  int _anno;
  sidejacking_record* _record_head = NULL;

 public:
  SIDEJACKING() CLICK_COLD;
  ~SIDEJACKING() CLICK_COLD;

  const char* class_name() const { return "SIDEJACKING"; }
  const char* port_count() const { return PORTS_1_1; }

  bool can_live_reconfigure() const { return true; }

  int initialize(ErrorHandler* errh);
  sidejacking_record* check_cookie_exist(char*);
  bool add_record(char*, int, char*);
  virtual void push(int port, Packet* p);
};

CLICK_ENDDECLS
#endif
