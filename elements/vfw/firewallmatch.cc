#include <click/config.h>
#include "firewallmatch.hh"
#include "firewalltable.hh"

CLICK_DECLS

enum action 
firewallmatch::domatch(Packet* p)
{
    enum action ret = DROP;    
    const uint8_t *pdata; 
    const struct click_ip *iph = p->ip_header();
    //int ip_len = ntohs(iph->ip_len);
    //int payload_len = ip_len - (iph->ip_hl << 2);
    struct entry te;   
    
    /* First, make an entry from the packet. */
    te.action = DROP;      // This is not used.
    te.src_ip = (uint32_t)(iph->ip_src.s_addr);
    te.des_ip = (uint32_t)(iph->ip_dst.s_addr);
    te.src_ip_mask = 4294967295; // mask is 255.255.255.255
    te.des_ip_mask = 4294967295; // mask is 255.255.255.255

    te.protocol = (uint8_t)(iph->ip_p);
    switch ( te.protocol ) {
        default: {
            //printf("WARNNING: Unknow protocol for IP packet!\n");
            /* Fall through */
        }
        /* ICMP */
        case 1: {
            te.src_port_min = 0;
            te.src_port_max = 0;
            te.des_port_min = 0;
            te.des_port_max = 0;
            break;
        }
        /* TCP, UDP */
        case 6: case 17: {
            pdata = (uint8_t*)((uint8_t*)iph + (iph->ip_hl << 2)); 
            te.src_port_min = ntohs(*(uint16_t*)pdata);
            te.src_port_max = te.src_port_min;
            te.des_port_min = ntohs(*(uint16_t*)(pdata+2));
            te.des_port_max = te.des_port_min;
            break;
        }
    }

    // If it's an TCP packet, then apply state table. 
    if ( 6 == te.protocol ) {
        struct state_entry* se = ft->get_firewall_states()->fs_check_entry(p);
        // If this packet matches a state entry. 
        if ( NULL != se ) {
            // update state.
            int result = ft->get_firewall_states()->fs_update_state(p, se);
            if ( 0 != result ) {
                ret = ALLOW;
            }
        // If this packet could not match a state entry. 
        } else {
            // search firewall rules and add a new state entry if necessary. 
            ret = ft->ft_match_entry(&te, p);
        }
    // If it's not a TCP packet. (Now it's considered as UDP and ICMP) 
    } else {
        /* Then, compare this entry to each of the rule. */
        ret = ft->ft_match_entry(&te);
        
    }

    // printEntry(&te);
    // If there is no matched, then return DROP.
    return ret;
}


void
firewallmatch::push(int port, Packet *p)
{  
    switch ( port ) {
        /* normal traffic. */
        case 0 : {
            enum action res;
            if ( NULL == p ) {
                return;
            }
            if ( (res = domatch(p)) == ALLOW ) {
#ifdef DEBUGTIMER_ACTIVE
            const struct click_ip *iph = p->ip_header();
                switch ((uint8_t)(iph->ip_p)) {
                    // UDP
                    case 17: {
                        ft->_PassUDP++; break;
                    } 
                    case 6: {
                        ft->_PassTCP++; break;
                    }
                    default: {
                        ft->_PassOther++; break;
                    }
                }
#endif
                checked_output_push(0, p);
            } else if ( DROP == res ) {
#ifdef DEBUGTIMER_ACTIVE
            const struct click_ip *iph = p->ip_header();
                switch ((uint8_t)(iph->ip_p)) {
                    // UDP
                    case 17: {
                        ft->_DropUDP++; break;
                    } 
                    case 6: {
                        ft->_DropTCP++; break;
                    }
                    default: {
                        ft->_DropOther++; break;
                    }
                }
#endif
                checked_output_push(2, p);
            } else {
#ifdef DEBUGTIMER_ACTIVE
                ft->_DropOther++;        
#endif
                p->kill();
            }
            break;
        }
        /* from tag detector. It's tagged packet. */
        case 1 : {
            checked_output_push(1, p);
            break;
        }
        default: break;
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(firewallmatch)
ELEMENT_MT_SAFE(firewallmatch)
