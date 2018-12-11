#ifndef CLICK_VIDS_PACKET_TAGS_HH
#define CLICK_VIDS_PACKET_TAGS_HH
#include <click/packet.hh>

CLICK_DECLS

/** @brief Encapsulating the tags into the Variable
 * Length Options of Geneve Header.
 * ( https://tools.ietf.org/html/draft-ietf-nvo3-geneve-00#section-3.1 )
 */

#define MAX_GENEVE_OPT_LEN 64

#define PTAG_CMD_DEF(cmd) PTAG_##cmd,

enum ptag_t {
#include "packet_tags.def"

  // detector type
  DNS_DETECTOR = 256,
  MLTSTP_DETECTOR,
  SIDEJACKING_DETECTOR,
  PORTSCAN_DETECTOR,

  FLOWBYTE_DETECTOR,
  PERFLOW_DETECTOR,

};

#undef PTAG_CMD_DEF

void set_tag(Packet*, ptag_t);
void del_tag(Packet*, ptag_t);
bool get_tag(Packet*, ptag_t);

CLICK_ENDDECLS

#endif
