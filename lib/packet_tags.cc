#include <click/config.h>
#include <click/logger.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/geneve.h>
#include "elements/vids/packet_tags.hh"

CLICK_DECLS
/**@brief Defined in GeneveEncap
 */
extern int geneve_opt_len;

static uint8_t _tag_configs[3][MAX_GENEVE_OPT_LEN*8] = {
    // [index in the user_anno, anno_mask], each index can store 8 tags
    // @note sorry, unimplemented: non-trivial designated initializers not supported. I could not initialize it like [PTAG_DNS_TUNNEL] = {0, 0b1},
    // @note Once a ptag_t is added in the header, change the _tag_configs at the same time
    {0, 0},   /* PTAG_NONE */
    {0, 0b1}, /* PTAG_MLTSTP */
    {0, 0b10} /* PTAG_DNS_TUNNEL */
};

#define _PROCESS_TAG(p, tag, action) \
    if(NULL == p) \
    { \
        LOG_ERROR("Packet pointer invalid"); \
        action; \
    } \
    if(tag < 0 || tag >= geneve_opt_len*8) \
    { \
        LOG_ERROR("ptag_t invalid"); \
        action; \
    } \
    int anno_index = _tag_configs[tag][0]; \
    int anno_mask = _tag_configs[tag][1]; \
    uint8_t *geneve_opt = (uint8_t*)p->data() + 14 + sizeof(click_ip) + \
            sizeof(click_udp) + sizeof(click_geneve);

void set_tag(Packet *p, ptag_t tag)
{
    _PROCESS_TAG(p, tag, return)
    geneve_opt[anno_index] |= anno_mask;
}

void del_tag(Packet *p, ptag_t tag)
{
    _PROCESS_TAG(p, tag, return)
    geneve_opt[anno_index] &= (0xff - anno_mask);
}

bool get_tag(Packet *p, ptag_t tag)
{
    _PROCESS_TAG(p, tag, return false)
    return geneve_opt[anno_index] == (geneve_opt[anno_index] | anno_mask);
}
#undef _PROCESS_TAG

CLICK_ENDDECLS

