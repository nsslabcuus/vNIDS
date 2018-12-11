#include <click/config.h>
#include <click/packet.hh>
#include <click/logger.h>

#include "elements/vids/event.hh"

CLICK_DECLS

#define IP_PROTO_EVENT 0xe0

/*
 * @note copy from Virtual Firewall's fwmanager::make_network_packet
 */
WritablePacket *make_network_packet(const uint8_t *data, uint32_t len, uint8_t ip_p = 0xfd)
{
    uint32_t hsz = sizeof(struct click_ip);
    WritablePacket *p = Packet::make(48,             // headroom, default=48, 4 bytes aligned.
                                     data,           // data to copy into the payload.
                                     len + hsz + 14, // header size + payload length.
                                     8);             // tailroom, default=0.
    if (NULL == p)
    {
        return NULL;
    }
    // set ip header.
    struct click_ip *iph = reinterpret_cast<struct click_ip *>(p->data() + 14);
    memset(p->data(), 0x0, hsz);
    iph->ip_v = 4;
    iph->ip_hl = sizeof(struct click_ip) >> 2;
    iph->ip_len = htons(p->length() - 14);
    uint16_t ip_id = 0x0001;
    iph->ip_id = htons(ip_id);
    iph->ip_p = ip_p;
    iph->ip_off = 0x0;
    iph->ip_ttl = 200;
    (iph->ip_src).s_addr = (uint32_t)0x10101010; // 16.16.16.16. Does not need htonl()
    (iph->ip_dst).s_addr = (uint32_t)0x01010101; // 1.1.1.1. Does not need htonl()
    iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(struct click_ip));
    // set annotation.
    p->set_dst_ip_anno(IPAddress(iph->ip_dst));
    p->set_ip_header(iph, sizeof(struct click_ip));
    p->timestamp_anno().assign_now();

    unsigned short *ptr = (unsigned short *)(p->data() + 12);
    *ptr = 0x08;
    // copy data.
    if (NULL != data)
    {
        memcpy(p->data() + 14 + hsz, data, len);
    }
    return p;
}

/*
 * @param ip_p protocol: 0xe0, indicate the payload is an event data
 */
WritablePacket *make_event_packet(const event_t *event)
{
    if (NULL == event)
        return NULL;
    WritablePacket *p = make_network_packet((const uint8_t *)event,
                                            event->event_len + sizeof(event_t),
                                            IP_PROTO_EVENT);
    return p;
}

event_t *extract_event(const Packet *p)
{
    if (!p->has_network_header())
        return NULL;
    if (IP_PROTO_EVENT != p->ip_header()->ip_p)
        return NULL;
    event_t *event = (event_t *)(p->network_header() + sizeof(click_ip));
    if ((const unsigned char *)(event->data + event->event_len) > p->end_data())
    {
        LOG_WARN("extract_event failed");
        return NULL;
    }
    return event;
}

CLICK_ENDDECLS
