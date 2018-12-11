#ifndef __CLICK_VIDS_EVENT__
#define __CLICK_VIDS_EVENT__

#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <stdarg.h>
#include <click/packet.hh>

CLICK_DECLS

/** @brief 5-tuples connect info
 */
struct connect_info_t {
  in_addr src_ip;
  in_addr dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  char protocol;
};

/** @brief event types
 */
enum event_type_t {
  // Multisteps
  FTP_REQUEST,
  FTP_DATA_ACTIVITY,
  FTP_DOWNLOAD_ZIP,
  HTTP_RESPONSE_HTML,
  HTTP_RESPONSE_EXE,
  HTTP_RESPONSE_ZIP,
  HTTP_REQUEST,
  SSH_AUTH_ATTEMPED,
  // Sidejacking
  HTTP_COOKIE_USERAGENT,
  // DNS Tunnels
  DNS_REQUEST,
  DNS_REPLY,
  NEW_CONNECTION,
  // must be last
  EVENT_TYPE_COUNT
};

/** @brief event struct
 */
struct event_t {
  event_type_t event_type; /*!< event type */
  uint32_t event_len;      /*!< len of data field */
  /** @brief DataWriter is a function object that used to fill the event data
   */
  struct DataWriter {
    DataWriter(char* buf) : _data(buf), _offset(0) {}

    template <class Tdata>
    DataWriter& operator()(Tdata data) {
      memcpy(_data + _offset, &data, sizeof(Tdata));
      _offset += sizeof(Tdata);
      return *this;
    }
    template <class Tdata>
    DataWriter& operator()(uint32_t len, Tdata* data) {
      (*this)(len);
      memcpy(_data + _offset, data, len * sizeof(Tdata));
      _offset += len * sizeof(Tdata);
      return *this;
    }

   private:
    char* _data;
    uint32_t _offset;
  };

  /** @brief will fill *count* fields in data <br/>
   * each fields contains two arguments: uint8_t len, char* buf
   */
  DataWriter get_writer() { return DataWriter(data); }

  /** @brief fill connect info <br/>
   */
  inline void fill_connect(Packet* p) {
    const click_ip* ip = p->ip_header();
    connect.src_ip = ip->ip_src;
    connect.dst_ip = ip->ip_dst;
    connect.protocol = ip->ip_p;
    if (IP_PROTO_TCP == ip->ip_p) {
      connect.src_port = ntohs(p->tcp_header()->th_sport);
      connect.dst_port = ntohs(p->tcp_header()->th_dport);
    } else if (IP_PROTO_UDP == ip->ip_p) {
      connect.src_port = ntohs(p->udp_header()->uh_sport);
      connect.dst_port = ntohs(p->udp_header()->uh_dport);
    }
  }
  connect_info_t connect;
  char data[0];
};

/** @brief alloc event_t <br/>
 */
static inline event_t* _alloc_event_data(uint32_t event_len) {
  event_t* event = (event_t*)calloc(1, sizeof(event_t) + event_len);
  event->event_len = event_len;
  return event;
}

/** @brief calculate event_len from fields' length
 */
static inline uint32_t _cal_event_len(int count, va_list fields_list) {
  uint32_t event_len = 0;
  while (count-- > 0) {
    // may allocate more than needed, since every field_len plus 4
    event_len += va_arg(fields_list, int) + sizeof(int);
  }
  return event_len;
}

/** @brief allocate event_t
 */
static inline event_t* alloc_event_data(int count, ...) {
  va_list fields_list;
  va_start(fields_list, count);
  uint32_t event_len = _cal_event_len(count, fields_list);
  va_end(fields_list);
  return _alloc_event_data(event_len);
}

/** @brief dealloc memory of event
 */
static inline void dealloc_event(event_t* event) {
  if (event) free(event);
}

/** @brief make packet from event data
 */
WritablePacket* make_event_packet(const event_t*);

/** @brief extract event data from packet data
 */
event_t* extract_event(const Packet*);

CLICK_ENDDECLS
#endif
