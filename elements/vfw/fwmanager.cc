#include <click/config.h>
#include "fwmanager.hh"

CLICK_DECLS
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)
// This feature is used for printing debug info. Comment out this 
// line to turn off the debug info. 
#define FWMANAGER_DEBUG_ON 1

/**
 *  struct rule. 
 *  This struct defines the format of rules that are transimtted over network.
 *  That is to say, firewall rule is in this formant when they are transmitted 
 *  over the network. 
 *
 *  A firewall rule must be converted to this format before it can be transmitted
 *  over network. Once a rule is received from the network by a recipient, it 
 *  must be firstly parsed using this data structure and then be converted into 
 *  an appropriate formant. E.g., the format of 'struct entry', which is defined
 *  in firewalltable.hh. 
 *  
 *  The size of this data structure determines how many rules can be transmitted
 *  over network in a time, by one IP packet. 
 *
 ***/
struct rule {
    uint32_t src_ip;
    uint32_t src_ip_mask;
    uint32_t dst_ip;
    uint32_t dst_ip_mask;
    uint16_t src_port_min;
    uint16_t src_port_max;
    uint16_t dst_port_min;
    uint16_t dst_port_max;
    uint8_t protocol;
    uint8_t action;
    // for 'seq' when migration; or 'index' when insert and replace 
    uint16_t index; 
};
#define RULE_SIZE 28

struct record {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t life_time;
    uint32_t syn1_ack;
    uint32_t syn2_ack;
    uint32_t fin1_ack;
    uint32_t fin2_ack;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t state;
    uint16_t seq;
};
#define RECORD_SIZE 36

enum OPTION_COMMANDS { C_APPEND, C_REPLACE, C_INSERT, C_DELETE, C_CHECK, C_CLEAR,
                       C_P_APPEND, C_P_APPEND_END, C_P_DELETE, C_P_DELETE_END };
enum OPTION_DEBUG { D_PRINT };
enum OPTION_STATE { S_STATE };

const char* readable_fm_state[] = {
    "NORMAL",
    "P_APPEND",
    "P_DELETE",
    "P_APPEND_END",
    "P_DELETE_END"
};



fwmanager::fwmanager():
    ft(g_ft),
    _state(NORMAL),
    _timer(this)
{
    for ( int i = 0; i < 6; ++i ) {
        ether_dhost[i] = 0;
        controller_dhost[i] = 0;
    }
}

bool
fwmanager::fm_append_entry(struct exentry* exe)
{
    bool ret = true;
    for (int i = 0; i < exe->entry_num; i++)
        ret &= ft->ft_append_entry(&exe->entry[i]);
    
    return ret;
}

bool 
fwmanager::fm_replace_entry(struct exentry* exe, uint16_t* indexes)
{
    bool ret = true;
    for (int i = 0; i < exe->entry_num; i++){ 
        ret &= ft->ft_replace_entry(&exe->entry[i], (int)(indexes[i])); 
    }
    return ret;
}

/**
*   Note: if insert a set of entries at a time, 
*   the index may be changed after each insertion.  
***/
bool 
fwmanager::fm_insert_entry(struct exentry* exe, uint16_t* indexes)
{  
    if ( NULL == indexes ) {
        return false;
    }
    bool ret = true;
    for(int i = 0; i < exe->entry_num; i++)
        ret &= ft->ft_insert_entry(&exe->entry[i], (int)(indexes[i]));

    return ret;
}

bool
fwmanager::fm_delete_entry(struct exentry* exe)
{
    bool ret = true;
    for(int i = 0; i < exe->entry_num; i++)
        ret &= ft->ft_delete_entry(&exe->entry[i]);

    return ret;
}

bool
fwmanager::fm_check_entry(struct exentry* exe)
{
    bool ret = true;
    for(int i = 0; i < exe->entry_num; i++)
        ret &= ft->ft_check_entry(&exe->entry[i]);

    return ret;
}

int 
fwmanager::fm_clear()
{
#ifdef DEBUGTIMER_ACTIVE
    ft->ft_clear_debug();
#endif
    return ft->ft_clear();
}

void 
fwmanager::fm_print()
{
    ft->ft_print();
}


/*
 *  This function will be called when a packet that contains firewall 
 *  rules is received. 
 *
 *  Note:
 *      During a migration, the firewall cannot receive controller's 
 *      command. All the commands are considered from the other 
 *      peer, unless the local firewall is not in P_APPEND state. 
 *
**/
void 
fwmanager::push(int port, Packet* p) {
    // from control channel. (eth2)
    if ( 1 == port ) {
        const struct click_ip *iph = p->ip_header();
        // check if it's a command message. 
        if ( 0xfd == iph->ip_p ) {
            if ( P_APPEND == _state ) {
                fm_demultiplex_from_peer(port, p);
            } else {
                fm_demultiplex_from_controller(port, p);
            }
        }
        p->kill();
    // from firewallmatch. It's a tagged packet. 
    } else if ( 0 == port ) {
        const struct click_ip *iph = p->ip_header();
        switch (iph->ip_p) {
            /* TCP */
            case 0x06 : {
                // update states. 
                ft->ft_update_state_by_tag(p);
                break;
            }
            /* UPD, ICMP, other packets or Pacer */
            default: {
                // update rules. 
                ft->ft_update_rule_by_tag(p);
                break;
            }
        } 
        if ( ft->ft_get_ipt()->delete_refs <= 0 ) {
            if ( 0 == fm_enforce_delete() ) {
                fprintf(stderr, "[fetal] fwmanager: enforce_delete faild!\n");
                fflush(stderr);
                while(1); 
            }
        } 
        p->kill();
    }
    return;
}

// stateful firewall migration. (replace, insert may use)
int 
fwmanager::fm_demultiplex_from_peer(int port, Packet* p) {
    UNUSED(port);
    const click_ip *iph = p->ip_header();
    uint8_t* pdata = (uint8_t*)(iph) + (iph->ip_hl << 2);
    struct exentry *ep = NULL; 
    struct exstate_entry *es = NULL;
    switch ( pdata[0] ) {
        default: {
            fprintf(stderr, "[error] fwmanager: Could not parse mode, from peer.\n");
            fflush(stderr);
            goto BadFromPeer;
        }
        /* command from peer. */
        case 0 : {
            switch ( pdata[1] ) {
                default: {
                    fprintf(stderr, "[error] fwmanager: Could not parse option(mode-1), from peer.\n");
                    fflush(stderr);
                    goto BadFromPeer;
                }
                /* append a rule. */
                case C_APPEND : {
                    fprintf(stdout, "Receive rules from peer.\n");
                    if ( 0 == fm_packet_to_exentry(ep, p, pdata+2) ){
                        fprintf(stderr, "[warn] fwmanager: Fail to append rule, from peer.\n");
                        fflush(stderr);
                        goto BadFromPeer;
                    } 
                    if ( 0 == fm_add_to_append(ep) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to append rule, from peer.\n");
                        fflush(stderr);
                        goto BadFromPeer;
                    } else {
                        fprintf(stdout, "appended %d rules from peer. [%u]\n",
                               ep->entry_num, ft->ft_get_size()) ;
                    }
                    break;
                }
                /* p_append_end. */
                case C_P_APPEND_END : {
                    if ( 0 == fm_enforce_append() ) {
                        fprintf(stderr, "[fetal] fwmanager: Could not enforce append.\n");
                        fflush(stderr);
                        while(1);
                    } else {
                        fprintf(stdout, "Move completes!\n") ;
                    }
                    break;
                }
            }
            break;
        }
        /* state from peer. */
        case 2 : {
#ifdef FWMANAGER_DEBUG_ON
            fprintf(stdout, "receive states from peer.\n");
            fflush(stdout);
#endif
            switch ( pdata[1] ) {
                default: {
                    fprintf(stderr, "[error] fwmanager: Could not parse option(mode-2), from peer.\n");
                    fflush(stderr);
                    goto BadFromPeer;
                }
                case S_STATE: {
                    if ( 0 == fm_packet_to_exstate(es, p, pdata+2) ) {
                        goto BadFromPeer;
                    } 
                    if ( 0 == fm_attach_state(es) ) {
                        goto BadFromPeer;
                    } else {
                        fprintf(stdout, "Add %d states from peer!\n", es->entry_num) ;
                    }
                    break;
                }
            }
            break;
        }
    }

    if ( NULL != ep ) {
        CLICK_LFREE(ep, ep->length);
    }
    if ( NULL != es ) {
        CLICK_LFREE(es, es->length);
    }
    return 1;

BadFromPeer:
    if ( NULL != ep ) {
        CLICK_LFREE(ep, ep->length);
    }
    if ( NULL != es ) {
        CLICK_LFREE(es, es->length);
    }
    return 0;
}

int 
fwmanager::fm_demultiplex_from_controller(int port, Packet* p) {
    UNUSED(port);
    const click_ip *iph = p->ip_header();
    uint8_t* pdata = (uint8_t*)(iph) + (iph->ip_hl << 2);
    struct exentry *ep = NULL; 
    uint16_t *indexes = NULL;
    switch ( pdata[0] ) {
        default: {
            fprintf(stderr, "[error] fwmanager: Could not parse mode.\n");
            fflush(stderr);
            goto BadFromController;
        }
        /* command from controller. */
        case 0 : {
            switch( pdata[1] ) {
                default: {
                    fprintf(stderr, "[error] fwmanager: Could not parse option(mode-1).\n");
                    fflush(stderr);
                    goto BadFromController;
                }
                /* append a rule. */
                case C_APPEND : {
#ifdef FWMANAGER_DEBUG_ON
                    uint32_t rule_count = ft->ft_get_size();
#endif
                    if ( 0 == fm_packet_to_exentry(ep, p, pdata+2) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to append rule.\n");
                        fflush(stderr);
                        goto BadFromController;
                    }
                    if ( true != fm_append_entry(ep) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to append rule.\n");
                        fflush(stderr);
                        goto BadFromController;
                    } else {
#ifdef FWMANAGER_DEBUG_ON
                        rule_count = ft->ft_get_size() - rule_count; 
                        fprintf(stdout,"%d rules have been installed [%u]\n", 
                                rule_count, ft->ft_get_size());
#endif
                    }
                    break;
                }
                /* delete a rule. */
                case C_DELETE : {
                    if ( 0 == fm_packet_to_exentry(ep, p, pdata+2) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to  delete rule.\n");
                        fflush(stderr);
                        goto BadFromController;
                    }
                    if ( true != fm_delete_entry(ep) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to delete rule.\n");
                        fflush(stderr);
                        goto BadFromController;
                    }
                    break;
                }
                /* insert a rule. */
                case C_INSERT : {
                    if ( 0 == fm_packet_to_exentry(ep, indexes, p, pdata+2) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to  insert rule.\n");
                        fflush(stderr);
                        goto BadFromController;
                    }
                    if ( true != fm_replace_entry(ep, indexes) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to insert rule.\n");
                        fflush(stderr);
                        goto BadFromController;
                    }
                    break;
                }
                /* replace a rule. */
                case C_REPLACE : {
                    if ( 0 == fm_packet_to_exentry(ep, indexes, p, pdata+2) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to replace rule.\n");
                        fflush(stderr);
                        goto BadFromController;
                    }
                    if ( true != fm_replace_entry(ep, indexes) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to replace rule.\n");
                        fflush(stderr);
                        goto BadFromController;
                    }
                    break; 
                }
                /* clear */ 
                case C_CLEAR : {
                    if ( 0 == fm_clear() ) {
                        fprintf(stderr, "[error] fwmanager: Fail to clear all rules/states.\n");
                        fflush(stderr);
                        goto BadFromController;
                    } else {
                        fprintf(stdout, "Rules/States cleared! [%u]\n", ft->ft_get_size());
                    }
                    break;
                }
                /* p_delete */
                case C_P_DELETE : {
#ifdef FWMANAGER_DEBUG_ON
                    fprintf(stdout, "Receive p_delete from controller.\n");
                    fflush(stdout);
                    uint32_t ole_delete_size = ft->ft_get_ipt()->_delete_size_;
#endif
                    if ( 0 == fm_packet_to_exentry(ep, p, pdata+8) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to parse p_delete\n");
                        fflush(stderr);
                        goto BadFromController;
                    }
                    memcpy(ether_dhost, pdata+2, 6);
                    if ( 0 == fm_add_to_delete(ep) ) {
                        fprintf(stderr, "[warn] fwmanager: Fail to add_to_delete.\n");
                        fflush(stderr);
                    } else {
#ifdef FWMANAGER_DEBUG_ON
                        fprintf(stdout, "Add %u rules to delete [delete size: %u]\n",
                               ft->ft_get_ipt()->_delete_size_ - ole_delete_size, 
                                ft->ft_get_ipt()->_delete_size_);
                        fflush(stdout);
#endif
                    }
                    // send a message to turn on the tagDetector element. 
                    fm_notify_detector(true);
                    break;
                }
                /* p_delete_end */
                case C_P_DELETE_END : {
                    fprintf(stdout, "Receive p_delete_end from controller. \n");
#ifdef FWMANAGER_DEBUG_ON
                    uint8_t old_state = _state;
#endif
                    _state = P_DELETE_END;
#ifdef FWMANAGER_DEBUG_ON
                    fprintf(stdout,"State Switched: [%s] -> [%s]\n", 
                            readable_fm_state[old_state], readable_fm_state[_state]);
                    fflush(stdout);
#endif
                    break;
                }
                /* p_append */
                case C_P_APPEND : {
                    // record controller's MAC. Assume it's is ethernet packet.
                    memcpy(controller_dhost, p->data()+6, 6);
#ifdef FWMANAGER_DEBUG_ON
                    fprintf(stdout, "controller's MAC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
                          controller_dhost[0], controller_dhost[1], controller_dhost[2],
                          controller_dhost[3], controller_dhost[4], controller_dhost[5]);
                    fflush(stdout);
#endif
                    if ( NORMAL != _state ) {
                        fprintf(stderr, "[warn] fwmanager: Receive p_append, current fwmanager state: %s\n",
                                readable_fm_state[(uint8_t)_state]); 
                        fflush(stderr);
                        goto BadFromController;
                    }
                    memcpy(ether_dhost, pdata+2, 6);
#ifdef FWMANAGER_DEBUG_ON
                    uint8_t old_state = _state;
#endif
                    _state = P_APPEND;
#ifdef FWMANAGER_DEBUG_ON
                    fprintf(stdout,"State Switched: [%s] -> [%s]\n", 
                            readable_fm_state[old_state], readable_fm_state[_state]);
                    fflush(stdout);
#endif
                    break;
                }
            }
            break;
        }
    } 

    if ( NULL != ep ) {
        CLICK_LFREE(ep, ep->length);
    }
    if ( NULL != indexes ) {
        delete[] indexes;
    }
    return 1;

BadFromController:
    if ( NULL != ep ) {
        CLICK_LFREE(ep, ep->length);
    }
    if ( NULL != indexes ) {
        delete[] indexes;
    }
    return 0;
}

/**
 *  make exentry and indexes from a packet. 
 *  It's the caller's responsibility to free the packet. 
 *
 *  exe     :   exentry that is going to convert to.  (Not allocated yet.)
 *  indexes :   indexes that is going to be filled up. (Not allocated yet.)
 *  p       :   packet. 
 *  pdata   :   packet payload, begins right from 'number of rules' field. 
 *
 *  return: 
 *      0 - fail. 
 *      1 - successful.
 * */
int 
fwmanager::fm_packet_to_exentry(struct exentry*& exe, uint16_t*& indexes, 
                                Packet* p, uint8_t* pdata) 
{
    UNUSED(p);
    /* current offset of payload. */
    uint8_t *offset = NULL;
    uint16_t ruleCount = 0;
    uint16_t currentRule = 0;
    struct rule r;
    
    //pdata = ((uint8_t*)(iph))+(iph->ip_hl << 2);
    ruleCount = ntohs(*(uint16_t*)(pdata));
    /* allocate indexes. */
    indexes = (uint16_t*)CLICK_LALLOC(sizeof(uint16_t)*ruleCount);
    /* allocate exentry. */
    exe = (struct exentry*)CLICK_LALLOC(sizeof(struct exentry) +
            sizeof(struct entry)*ruleCount);
    if ( NULL == exe ) {
        fprintf(stderr, "[error] fwmanager: Could not make exentry from packet.(no memory)\n");
        fflush(stderr);
        return 0;
    }
    exe->length = sizeof(struct exentry) + sizeof(struct entry)*ruleCount;
    exe->entry_num = ruleCount;
    exe->elength = sizeof(struct entry)*ruleCount;
    /* fulfill entries. */
    offset = pdata+2;
    for ( currentRule = 0; currentRule < ruleCount; ++currentRule ) {
        memcpy(&r, offset, RULE_SIZE);
        offset += RULE_SIZE;
        (exe->entry)[currentRule].src_ip = r.src_ip;
        (exe->entry)[currentRule].src_ip_mask = r.src_ip_mask;
        (exe->entry)[currentRule].des_ip = r.dst_ip;
        (exe->entry)[currentRule].des_ip_mask = r.dst_ip_mask;
        (exe->entry)[currentRule].protocol = r.protocol;
        (exe->entry)[currentRule].src_port_min = ntohs(r.src_port_min);
        (exe->entry)[currentRule].src_port_max = ntohs(r.src_port_max);
        (exe->entry)[currentRule].des_port_min = ntohs(r.dst_port_min);
        (exe->entry)[currentRule].des_port_max = ntohs(r.dst_port_max);
        (exe->entry)[currentRule].action = (enum action)(r.action);
        (exe->entry)[currentRule].connection = NULL;
        indexes[currentRule] = (uint16_t)ntohs(r.index);
        /* recall that there is still a '\n' */
        if ( '\n' != *offset ) {
            fprintf(stderr, "[error] fwmanager: broken commands received.\n");
            fflush(stderr);
            return 0;
        }
        offset++;
    } 
    return 1;
}

/**
 *  make exentry from a packet. (append, delete may use)
 *  
 *  exe     :   exentry that is going to convert to.  (Not allocated yet.)
 *  p       :   packet. 
 *  pdata   :   packet payload, begins right from 'number of rules' field. 
 *  
 *  return: 
 *      0 - fail. 
 *      1 - successful.
 * */
int 
fwmanager::fm_packet_to_exentry(struct exentry*& exe, Packet* p, uint8_t* pdata) {
    /* current offset of payload. */
    UNUSED(p);
    uint8_t *offset = NULL;
    uint16_t ruleCount = 0;
    uint16_t currentRule = 0;
    struct rule r;

    //pdata = ((uint8_t*)(iph))+(iph->ip_hl << 2);
    ruleCount = ntohs(*(uint16_t*)(pdata));
    /* allocate exentry. */
    exe = (struct exentry*)CLICK_LALLOC(sizeof(struct exentry) + 
            sizeof(struct entry)*ruleCount);
    if ( NULL == exe ) {
        fprintf(stderr, "[error] fwmanager: Could not make exentry from packet.(no memory)\n");
        fflush(stderr);
        return 0;
    }
    exe->length = sizeof(struct exentry) + sizeof(struct entry)*ruleCount;
    exe->entry_num = ruleCount;
    exe->elength = sizeof(struct entry)*ruleCount;
    /* fulfill entries. */
    offset = pdata+2;
    for ( currentRule = 0; currentRule < ruleCount; ++currentRule ) {
        memcpy(&r, offset, RULE_SIZE);
        offset += RULE_SIZE;
        (exe->entry)[currentRule].src_ip = r.src_ip;
        (exe->entry)[currentRule].src_ip_mask = r.src_ip_mask;
        (exe->entry)[currentRule].des_ip = r.dst_ip;
        (exe->entry)[currentRule].des_ip_mask = r.dst_ip_mask;
        (exe->entry)[currentRule].protocol = r.protocol;
        (exe->entry)[currentRule].src_port_min = ntohs(r.src_port_min);
        (exe->entry)[currentRule].src_port_max = ntohs(r.src_port_max);
        (exe->entry)[currentRule].des_port_min = ntohs(r.dst_port_min);
        (exe->entry)[currentRule].des_port_max = ntohs(r.dst_port_max);
        (exe->entry)[currentRule].action = (enum action)(r.action);
        (exe->entry)[currentRule].connection = NULL;
        (exe->entry)[currentRule].seq = ntohs(r.index);
        /* recall that there is still a '\n' */
        if ( '\n' != *offset ) {
            fprintf(stderr, "[error] fwmanager: broken commands received.\n");
            fflush(stderr);
            return 0;
        }
        offset++;
    }
    return 1;
}

/**
 *  The given exentry* is not going to be reallocated. 
 *  simply copy the content of the given entry* to the appropriate 
 *  location in exentry*. 
 *
 *  exe     :   a pointer to a pre-allocated buffer. 
 *  e       :   pointer to an entry. This entry will not be touched.  
 *
 *  return  : 
 *      0 - fail. 
 *      1 - successful.
 **/
int 
fwmanager::fm_add_entry_to_exentry(struct exentry* exe, int max_len, const struct entry* e) {
    if ( exe->entry_num >= max_len ) {
        return 0; 
    }
    memcpy(reinterpret_cast<uint8_t*>((exe->entry)+(exe->entry_num)), 
           reinterpret_cast<const uint8_t*>(e), 
           sizeof(*e));
    exe->entry_num++;
    exe->elength += sizeof(struct entry);
    return 1;
}

/**
 *  add the entries carried by the given exentry into the _delete_ link.
 *  Before calling this function, fm_packet_to_exentry must be called 
 *  first. 
 *  
 *  IMPORTANT NOTE: 
 *      This function will first find out rules that match agians the 
 *      given `exe`. 
 *      Then the function will append the matched rules to the _delete_ link. 
 *      The entries with in the given exentry will not be touched. 
 *
 *      If the function could not find any entry that matches any one entry 
 *      within the given exentry, then this function will do nothing. 
 *
 *  return:
 *      0 - fail. 
 *      1 - successful.
 * */
int 
fwmanager::fm_add_to_delete(struct exentry* exe) {
    int count = 0;
    int ret = 1;
    int found = 0;
    struct entry* real_entry = NULL;
    while ( count < exe->entry_num ) {
        // find the first entry who is not in _delete_. 
        real_entry = ft->ft_return_entry(static_cast<struct entry*>(exe->entry) + count, 1);
        if ( NULL != real_entry ) {
            // add rules to _delete_
            ret &= ft->ft_add_to_delete(real_entry);
            if ( 0x06 == real_entry->protocol ) {
                ret &= ft->ft_add_state_to_delete(real_entry);
            }
            found = 1;
        } else {
        }
        ++count;
    } 
    // Switch state to 'p_delete' 
    if ( 0 != found ) {
#ifdef FWMANAGER_DEBUG_ON
        uint8_t old_state = _state;
#endif
        _state = P_DELETE;
#ifdef FWMANAGER_DEBUG_ON
        fprintf(stdout, "State Switched: [%s] -> [%s]\n", 
                readable_fm_state[old_state],readable_fm_state[_state]);
        fflush(stdout);
#endif
    }
    return ret; 
}
/***
 *  given an exentry (normally from peer), append the entries in this 
 *  exentry to _append_ as well as at the tail of "ipt".
 *  New entries will be allocated. 
 *  The exentry can be delete after calling. 
 *
 *  return 
 *      0 - fail. 
 *      1 - successful.
 ***/
int 
fwmanager::fm_add_to_append(struct exentry* exe) {
    int ret = 1;
    for ( int i = 0; i < exe->entry_num; i++ ) {
        ret &= ft->ft_add_to_append(static_cast<struct entry*>(exe->entry)+i);
    }
    return ret;
}

/**
 *  This function converts an exentry to a packet. 
 *  The returned packet is a ethernet packet. 
 *  It's destination MAC address is valid, but it's source MAC address is not.
 *  
 *  exe     :   the given exentry. 
 *  mode    :   mode field to set to the packet. 0-command, 1-debug, 2-state.
 *  op      :   op_type. It can be one of the following: 
 *              enum OPTION_COMMANDS, enum OPTION_DEBUG or enum OPTION_STATE.
 *  ip_p    :   ip protocol. 0xfd - control message, 0xfe - activation message. 
 *
 *  return 
 *      NULL - fail. 
 *      WritablePacket pointer - successful.
 ***/
WritablePacket*
fwmanager::fm_exentry_to_packet(const struct exentry* exe, 
                                uint8_t mode=0, uint8_t op=C_APPEND, uint8_t ip_p=0xfd)
{
    if ( 0 == exe->entry_num ) {
        fprintf(stderr, "[error] fwmanager: exentry size=0 when convert to packet.\n");
        fflush(stderr);
        return NULL;
    }
    uint8_t* data = NULL;
    // (mode + op_type) + (2 bytes for number of rules) + (however rules)*(rule+'\n')
    uint32_t data_len = 2 + 2 + (exe->entry_num) * (sizeof(struct rule)+1);
    WritablePacket* p = NULL;
    WritablePacket* q = NULL;
    data = (uint8_t*)CLICK_LALLOC(data_len);
    if ( NULL != data ) {
        data[0] = mode;
        data[1] = op;
        *((uint16_t*)(data+2)) = htons((uint16_t)(exe->entry_num));
        int i = 0;
        for ( struct rule* offset = (struct rule*)(data+4);
                i < exe->entry_num; ++i ) {
            offset->src_ip = (exe->entry)[i].src_ip;
            offset->src_ip_mask = (exe->entry)[i].src_ip_mask;
            offset->dst_ip = (exe->entry)[i].des_ip;
            offset->dst_ip_mask = (exe->entry)[i].des_ip_mask;
            offset->src_port_min = htons((exe->entry)[i].src_port_min);
            offset->src_port_max = htons((exe->entry)[i].src_port_max);
            offset->dst_port_min = htons((exe->entry)[i].des_port_min);
            offset->dst_port_max = htons((exe->entry)[i].des_port_max);
            offset->protocol = (exe->entry)[i].protocol;
            offset->action = (uint8_t)((exe->entry)[i].action);
            offset->index = htons((exe->entry)[i].seq);
            offset++;
            *((uint8_t*)offset) = '\n';
            offset = (struct rule*)(((uint8_t*)offset)+1);
        }
        p = make_network_packet(data, data_len, ip_p);
        if ( NULL != p ) {
            q = make_ether_packet(p, ether_dhost);
        }
        CLICK_LFREE(data, data_len);
    }
    return q;
}

/**
 *  This functions receives a doubly linked list and trying to make packets 
 *  from the given states and push them out to output port #2. 
 *  Note: 
 *      This function may be costly if there are many states. 
 *      More than one packet will be crated and sent out, if the number 
 *      of the given states are larger than 35.
 *
 ***/
int 
fwmanager::fm_send_states() {
    uint32_t size = ft->ft_get_deleted_state_count();
    int ret = 1;
    while ( size > 0 ) {
        uint32_t actual_size = size > 35 ? 35 : size;
        struct exstate_entry *exs;
        uint32_t buf_len = sizeof(struct exstate_entry) + sizeof(struct state_entry)*actual_size;
        exs = static_cast<struct exstate_entry*>(CLICK_LALLOC(buf_len));
        if ( NULL == exs ) {
            fprintf(stderr, "[fetal] fwmanager: not enough memory to make exstate_entry.\n");
            fflush(stderr);
            while(1);
        }
        exs->length = buf_len;
        exs->entry_num = 0;
        exs->elength = exs->entry_num*sizeof(struct state_entry);
        // make one exstate_entry. 
        for ( uint32_t count = 0; count < actual_size; ++count ) {
            struct state_entry* s = ft->ft_pop_from_deleted_state();
            if ( NULL != s ) {
                ret &= fm_add_state_to_exstate(exs, actual_size, s);
                ++count;
                CLICK_LFREE(s, sizeof(*s));
            } else {
                CLICK_LFREE(exs, exs->length);
                fprintf(stderr, "[erro] fwmanager: trying pop from empty states link.\n");
                fflush(stderr);
                return 0;
            }
        }
        // send states to the other peer. 
        WritablePacket* p = fm_exstate_to_packet(exs, 2, S_STATE, 0xfd);
        if ( NULL != p ) {
            checked_output_push(2, p);
        } else {
            fprintf(stderr, "[warn] fwmanager: Could not make packet from exstate_entry.\n");
            fflush(stderr);
        }
        size = size - actual_size;
        CLICK_LFREE(exs, exs->length);
    }
    return ret;
}

int 
fwmanager::fm_add_state_to_exstate(struct exstate_entry* exs, int max_len, struct state_entry* s) {
    if ( exs->entry_num >= max_len ) {
        return 0;
    }
    memcpy(reinterpret_cast<uint8_t*>((exs->entry)+(exs->entry_num)),
           reinterpret_cast<const uint8_t*>(s),
           sizeof(*s));
    exs->entry_num++;
    exs->elength += sizeof(struct state_entry);
    return 1;
}

WritablePacket*
fwmanager::fm_exstate_to_packet(const struct exstate_entry* exs, 
                                uint8_t mode=2, uint8_t op=S_STATE, uint8_t ip_p=0xfd) 
{
    if ( 0 == exs->entry_num ) {
        fprintf(stderr, "[error] fwmanager: exstate size=0 when conver to packet.\n");
        fflush(stderr);
        return NULL;
    }
    uint8_t* data = NULL;
    uint32_t data_len = 2 + 2 + (exs->entry_num) * (sizeof(struct record)+1);
    WritablePacket* p = NULL;
    WritablePacket* q = NULL;
    data = (uint8_t*)CLICK_LALLOC(data_len);
    if ( NULL != data ) {
        data[0] = mode;
        data[1] = op;
        *((uint16_t*)(data+2)) = htons((uint16_t)(exs->entry_num));
        int i = 0;
        for ( struct record* offset = (struct record*)(data+4);
                i < exs->entry_num; ++i )
        {
            offset->src_ip = (exs->entry)[i].src_ip;
            offset->dst_ip = (exs->entry)[i].dst_ip;
            offset->life_time = htonl((exs->entry)[i].life_time);
            offset->syn1_ack = htonl((exs->entry)[i].syn1_ack);
            offset->syn2_ack = htonl((exs->entry)[i].syn2_ack);
            offset->fin1_ack = htonl((exs->entry)[i].fin1_ack);
            offset->fin2_ack = htonl((exs->entry)[i].fin2_ack);
            offset->src_port = htons((exs->entry)[i].src_port);
            offset->dst_port = htons((exs->entry)[i].dst_port);
            offset->protocol = (exs->entry)[i].protocol;
            offset->state = (uint8_t)((exs->entry)[i].state);
            offset->seq = htons((exs->entry)[i].seq);
            offset++;
            *((uint8_t*)offset) = '\n';
            offset = (struct record*)(((uint8_t*)offset)+1);
        }
        p = make_network_packet(data, data_len, ip_p);
        if ( NULL != p ) {
            q = make_ether_packet(p, ether_dhost);
        }
        CLICK_LFREE(data, data_len);
    }
    return q;
}


/***
 *  Detach all entries that are linked by _delete_, and make packet for 
 *  those entries, and then send them out. 
 *  If there are any states, send out the states, by making the states
 *  into packets. 
 *  
 *  Note: 
 *  There are only three ways to call this function: 
 *      1) receives a tagged packet and the packet triggers ipt->delete_refs to zero.
 *      2) receives a tagged packet and this packet is a pacer. 
 *      3) a timer flush will trigger a look at the `ipt->delete_refs`.
 *         `delete_refs` will change due to rules/states expiration. 
 *
 *  The 1) and 2) method will be triggered by fwmanager::push(), and the 3) methond will be 
 *  triggered by fm_check_delete_refs(). 
 *
 *  return
 *      0 - fail 
 *      1 - successful.
 * */
int 
fwmanager::fm_enforce_delete() {
    if ( NULL == ft->ft_get_ipt()->_delete_) {
        return 1;
    }
    uint32_t size = ft->ft_get_delete_size();
#ifdef FWMANAGER_DEBUG_ON
    uint32_t original_size = size;
#endif
    int ret = 1;
    while ( size > 0 ) {
        uint32_t actual_size = size > 45 ? 45 : size;
        struct exentry* exe;
        uint32_t buf_len = sizeof(struct exentry) + sizeof(struct entry)*actual_size;
        exe = static_cast<struct exentry*>(CLICK_LALLOC(buf_len));
        if ( NULL == exe ) {
            fprintf(stderr, "[fetal] fwmanager: not enough memory\n");
            fflush(stderr);
            while(1);
        }
        exe->length = buf_len;
        exe->entry_num = 0;
        exe->elength = exe->entry_num*sizeof(struct entry);
        uint32_t count = 0;
        while ( count < actual_size ) {
            struct entry* e = ft->ft_pop_from_delete();
            if ( NULL != e ) {
                ret &= fm_add_entry_to_exentry(exe, actual_size, e);
                ++count;
                CLICK_LFREE(e, sizeof(*e));
            } else {
                CLICK_LFREE(exe, exe->length);
                fprintf(stderr, "[error] fwmanager: trying pop from empty _delete_ link.\n");
                fflush(stderr);
                return 0;
            }
        }

        // send append rules to the other peer. 
        WritablePacket* rule_packet = fm_exentry_to_packet(exe, 0, C_APPEND, 0xfd);
        if ( NULL != rule_packet ) {
            checked_output_push(2, rule_packet);
            ret &= fm_send_states();
        } else {
            fprintf(stderr, "[warn] fwmanager: Could not make packet from exentry\n");
            fflush(stderr);
        }
        size = size - actual_size;
        CLICK_LFREE(exe, exe->length);
    }
    // send out p_append_end command to the other peer. 
    if ( P_DELETE_END == _state ) {
        ret &= fm_send_p_append_end();
    }


#ifdef FWMANAGER_DEBUG_ON
    size = ft->ft_get_delete_size();
    if ( original_size != size ) {
        fprintf(stdout, "%u rules have been deleted. [%u]\n", 
                original_size-size, ft->ft_get_size());
        fflush(stdout);
    }
#endif
    return ret; 
}


int 
fwmanager::fm_packet_to_exstate(struct exstate_entry*& exs, Packet* p, uint8_t* pdata) {
    UNUSED(p);
    uint8_t *offset = NULL;
    uint16_t stateCount = 0;
    uint16_t currentState = 0;
    struct record r;
    //pdata = (uint8_t*)(iph) + (iph->ip_hl << 2);
    stateCount = ntohs(*(uint16_t*)(pdata));
    exs = (struct exstate_entry*)CLICK_LALLOC(sizeof(struct exstate_entry) +
            sizeof(struct state_entry)*stateCount);
    if ( NULL == exs ) {
        fprintf(stderr, "[error] fwmanager: Could not make exentry from packet.(no memory)\n");
        fflush(stderr);
        return 0;
    }
    exs->length = sizeof(struct exstate_entry) + sizeof(struct state_entry)*stateCount;
    exs->entry_num = stateCount;
    exs->elength = sizeof(struct state_entry)*stateCount;
    /* fill out state_entry. */
    offset = pdata+2;
    for ( currentState = 0; currentState < stateCount; ++currentState ) {
        memcpy(&r, offset, RECORD_SIZE);
        offset +=RECORD_SIZE;
        (exs->entry)[currentState].src_ip = r.src_ip;
        (exs->entry)[currentState].dst_ip = r.dst_ip;
        (exs->entry)[currentState].src_port = ntohs(r.src_port);
        (exs->entry)[currentState].dst_port = ntohs(r.dst_port);
        (exs->entry)[currentState].protocol = r.protocol;
        (exs->entry)[currentState].state = (enum fw_state)(r.state);
        (exs->entry)[currentState].life_time = ntohl(r.life_time);
        (exs->entry)[currentState].syn1_ack = ntohl(r.syn1_ack);
        (exs->entry)[currentState].syn2_ack = ntohl(r.syn2_ack);
        (exs->entry)[currentState].fin1_ack = ntohl(r.fin1_ack);
        (exs->entry)[currentState].fin2_ack = ntohl(r.fin2_ack);
        (exs->entry)[currentState].seq = ntohs(r.seq);
        if ( '\n' != *offset ) {
            fprintf(stderr, "[error] fwmanager: broken state record received.\n");
            fflush(stderr);
            return 0;
        }
        offset++;
    }
    return 1;
}

struct entry* 
fwmanager::fm_find_appended_entry_by_seq(uint16_t seq) {
    return ft->ft_find_appended_entry_by_seq(seq);
}

/**
 *  Once the states get parsed by 'fm_packet_to_exstate', then 
 *  the exstate_entry will be passed to this function. 
 *  All the states will be attached appropriately to the appended entries, 
 *  according to the seq field. 
 *
 *  return 
 *      0 - fail. 
 *      1 - successful. 
 ***/
int 
fwmanager::fm_attach_state(struct exstate_entry* exs) {
    int ret = 1;
    for ( int i = 0; i < exs->entry_num; ++i ) {
        struct entry* tmp = fm_find_appended_entry_by_seq((exs->entry)[i].seq);
        if ( NULL != tmp ) {
            ret &= ft->ft_attach_state(tmp, (exs->entry)+i);
        } else {
            // suspend this state untill the expected entry arrives.
            ret &= ft->ft_suspend_state((exs->entry)+i);
            fprintf(stderr, "[warn] fwmanager: Could not find entry for state(seq=%hd).\n", 
                    (exs->entry)[i].seq);
            fflush(stderr);
        }
    }
    return ret;
}

/**
 *  Detach all the states from the entries in the given exentry. 
 *  And append them at 'deleted_state' link .
 *
 *  This function is NOT used!
 *
 **/
int 
fwmanager::fm_add_states_to_delete(struct exentry* exe) {
    struct entry* e;
    int entry_num = exe->entry_num;
    int ret = 1;
    for ( int count = 0; count < entry_num; ++count ) {
        e = (exe->entry) + count;
        // Only TCP has to add states to delete.
        if ( 0x06 == e->protocol ) {
            ret &= ft->ft_add_state_to_delete(e);
        }
    }
    return ret;
}

/**
 *  This function will be invoked when fwmanager receives 
 *  a p_append_end message. 
 *  Then this function will switch the state to NORMAL. 
 *  After this function, fwmanager will call fm_send_activation()
 *  to activate firewallmatch element. 
 *  
 *  return 
 *      0 - fail. 
 *      1 -successful.
 **/
int 
fwmanager::fm_enforce_append() {
    if ( 0 != ft->ft_enforce_append() ) {
        // send activation to firewallmatch. 
        if ( 0 != fm_send_activation() ) {
#ifdef FWMANAGER_DEBUG_ON
            uint8_t old_state = (uint8_t)_state;
#endif
            _state = NORMAL;
#ifdef FWMANAGER_DEBUG_ON
            fprintf(stdout,"State Switched: [%s] -> [%s]\n",
                    readable_fm_state[old_state], readable_fm_state[_state]);
            fflush(stdout);
#endif 
            if ( 0 == fm_notify_controller() ) {
#ifdef FWMANAGER_DEBUG_ON
                fprintf(stderr, "[error] fwmanager: Fail to notify controller.\n");
                fflush(stderr);
#endif 
            }
            return 1;
        }
    } 
    return 0;
}

/**
 *  This functions makes a packet and sends to:
 *      firewallmatch element
 *  to activate the firewallmatch, once all rules and states 
 *  are successfully install. 
 *  
 *  fwmanager's output 1 is connected to firewallmatch element.
 *
 *  return 
 *      0 - fail. 
 *      1 - successful.
 **/
int
fwmanager::fm_send_activation() {
    WritablePacket* p = make_network_packet(NULL, 0, 0xfe); 
    if ( NULL == p ) {
        fprintf(stderr,"[error] fwmanager: Could not make activation packet.\n");
        fflush(stderr);
        return 0;
    } else {
        checked_output_push(1, p); 
        return 1;
    }
}

/***
 *  This functions sends a notification to tagDetector element when 
 *  fwmanager receives a `p_delete` command from controller. 
 *  
 *  on  :   True is notify detector to turn on; False if notify detector to turn off.
 *
 *  return 
 *      0 - fail. 
 *      1 - successful.
 ***/
int 
fwmanager::fm_notify_detector(bool on) {
    uint8_t ip_p = 0xfe;
    if ( false == on ) {
        ip_p = 0xfd;
    }
    WritablePacket* p = make_network_packet(NULL, 0, ip_p); 
    if ( NULL != p ) {
        checked_output_push(0, p);
        return 1;
    } else {
        fprintf(stderr, "[error] fwmanager: Could not send notification to tagDetector!\n"); 
        fflush(stderr);
        return 0;
    }
}

/**
 *  This function sends out a `p_append_end` message to the other peer. 
 *  So that the other peer will know that all states/rules are transimtted. 
 *
 *  This functions will be called after all rules/states are sent out. 
 *  
 *  return 
 *      0 - fail. 
 *      1 - successful.
 **/
int 
fwmanager::fm_send_p_append_end() {
    uint8_t ip_p = 0xfd;
    uint8_t payload[2];
    payload[0] = 0x0;   // mode. 
    payload[1] = C_P_APPEND_END;  // op_type.
    WritablePacket *p  = make_network_packet(payload, 2, ip_p);
    if ( NULL != p ) {
        WritablePacket *q = make_ether_packet(p, ether_dhost);
        if ( NULL != q ) {
            checked_output_push(2, q);
            ft->ft_get_ipt()->_delete_size_ = 0;
            ft->ft_get_ipt()->delete_refs = 0;
            ft->ft_get_ipt()->delete_seq = 0;
#ifdef FWMANAGER_DEBUG_ON
            uint8_t old_state = _state;
#endif
            _state = NORMAL;
#ifdef FWMANAGER_DEBUG_ON
            fprintf(stdout, "P_APPEND_END sent!\n");
            fprintf(stdout,"State Switched: [%s] -> [%s]\n", 
                   readable_fm_state[old_state], readable_fm_state[_state]);
            fflush(stdout);
#endif
        } else {
            fprintf(stderr, "[error] fwmanager: cannot make p_append_end message.\n");
            fflush(stderr);
            return 0;
        }   
    } else {
            fprintf(stderr, "[error] fwmanager: cannot make p_append_end message.\n");
            fflush(stderr);
            return 0;
    }
#ifdef FWMANAGER_DEBUG_ON
    fprintf(stdout,"p_append_end message send!\n");
#endif
    
    // finally, send a notification to turn off the detector.
    fm_notify_detector(false);
    return 1;
}

/***
 *  This function push a mac header in front of the given packet. 
 *  The given packet must not be used any more. 
 *  
 *  14 bytes ether header. 
 *  Source MAC address is invalid. 
 *
 *  return 
 *      NULL - fail. 
 *      new pointer - successful.
 ****/
WritablePacket*
fwmanager::make_ether_packet(Packet* p, uint8_t* dst_mac) {
    if ( !p->has_network_header() || p->ip_header_offset() < 0 ) {
        fprintf(stderr, "[error] fwmanager: invalid ip packet!\n");
        fflush(stderr);
        p->kill();
        return NULL;
    }
    if ( p->ip_header_offset() >= 0 ) {
        // make ip_header_offset == 0        
        p->pull(p->ip_header_offset());
    }
    // push room for MAC header. 
    WritablePacket* q = p->push(14);
    if ( NULL != q ) {
        // set destination MAC. 0-5 bytes. 
        memcpy(q->data(), dst_mac, 6);
        // set ether type (IP).  12-13 bytes.  
        *((uint16_t*)(q->data()+12)) = htons(0x0800);
        // set annotation.
        q->set_mac_header(q->data(), 14);
        return q;
    } else {
        return 0;
    }
}

/**
 *  Given a `data`, and the length of the `data`, this function returns 
 *  a WritablePacket pointer. 
 *
 *  If the `data` is NULL, then WritablePacket is uninitialized. 
 *  `ip_p` will be set to the packet's ip_p field. 
 *      0xfd, normal commands 
 *      0xfe, activation commands
 * 
 *  return 
 *      NULL - fail. 
 *      pointer to WritablePacket - successful.
 ***/
WritablePacket*
fwmanager::make_network_packet(const uint8_t* data, uint32_t len, uint8_t ip_p = 0xfd) {
    uint32_t hsz = sizeof(struct click_ip);
    WritablePacket* p = Packet::make(48,        // headroom, default=48, 4 bytes aligned.
                                     data,      // data to copy into the payload.
                                     len+hsz,   // header size + payload length.  
                                     8);      // tailroom, default=0. 
    if ( NULL == p ) {
        return NULL;
    }
    // set ip header. 
    struct click_ip *iph = reinterpret_cast<struct click_ip*>(p->data());
    memset(p->data(), 0x0, hsz);
    iph->ip_v = 4;
    iph->ip_hl = sizeof(struct click_ip) >> 2;
    iph->ip_len = htons(p->length());
    uint16_t ip_id = 0x0001;
    iph->ip_id = htons(ip_id);
    iph->ip_p = ip_p;
    iph->ip_ttl = 200;
    (iph->ip_src).s_addr = (uint32_t)0x10101010; // 16.16.16.16. Does not need htonl()
    (iph->ip_dst).s_addr = (uint32_t)0x01010101; // 1.1.1.1. Does not need htonl()
    iph->ip_sum = click_in_cksum((unsigned char*)iph, sizeof(struct click_ip));
    // set annotation.
    p->set_dst_ip_anno(IPAddress(iph->ip_dst));
    p->set_ip_header(iph, sizeof(struct click_ip));
    p->timestamp_anno().assign_now();
    // copy data. 
    if ( NULL != data ) {
        memcpy(p->data()+hsz, data, len);
    }
    return p;
}

/***
 *  The fwmanager sends a notification to the controller when 
 *  the move completes, to notify the controller to update 
 *  the route.
 *
 *  return 
 *      0 - fail. 
 *      1 - successful.
 *
 ***/
int 
fwmanager::fm_notify_controller() {
    WritablePacket* p = make_network_packet(NULL, 0, 0xfc);
    if ( NULL != p ) {
        WritablePacket *q = make_ether_packet(p, controller_dhost);
        if ( NULL != q ) {
            checked_output_push(2, q);
            fprintf(stdout, "Notify controller!\b");
            fflush(stdout);
            return 1;
        } else {
            fprintf(stderr, "Could not make ether packet to controller hots.\n");
            fflush(stderr);
        }
    } else {
            fprintf(stderr, "Could not make IP packet to controller hots.\n");
            fflush(stderr);
    }
    return 0;
}


int 
fwmanager::initialize(ErrorHandler *errh) {
    UNUSED(errh);
    _timer.initialize(this);
    _timer.schedule_now();
    return 0;
}

void
fwmanager::run_timer(Timer* timer) {
    assert(timer == &_timer);
    fm_check_delete_refs();
    _timer.schedule_after_msec(delete_ref_check_cycle);
}

/**
 *  This functions will be called periodically.
 *  This function may invoke fm_enforce_delete, if necessary.
 *  
 *  return 
 *      0 - fail. 
 *      1 - successful.
 **/
int 
fwmanager::fm_check_delete_refs() {
    if ((NULL != ft->ft_get_ipt()->_delete_)&&
        (P_DELETE == _state || P_DELETE_END == _state)&&
        (ft->ft_get_ipt()->delete_refs == 0))
    {
        if ( 0 == fm_enforce_delete() ) {
            fprintf(stderr, "[fetal] fwmanager: enforce_delete faild!\n");
            fflush(stderr);
            while(1); 
        }
    } else if ( unlikely(P_DELETE_END==_state) && likely(NULL==ft->ft_get_ipt()->_delete_) ) {
        // This will switch state from P_DELETE_END to NORMAL.
        fm_send_p_append_end();
    }
    return 1;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(fwmanager)
ELEMENT_MT_SAFE(fwmanager)
