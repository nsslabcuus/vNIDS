#ifndef CLICK_NFV_FIREWALL_TABLE_HH
#define CLICK_NFV_FIREWALL_TABLE_HH

/***
*  This file defines firewall tables, including state table and 
*  rule table.  
*
*  The state table now only supports TCP flows. 
*  The state table is now under development. It does not track the 
*  sequnce number of each side of a TCP connection. Therefore, it 
*  is not able to fully support TCP connection state transfer. 
*  Here is an example that the state table will fail to work. 
*  
*  Assume the topology: 
*
*  Host A  ----------  Firewall  ----------  Host B. 
*           network1              network2
*             (N1)                  (N2)
*
*  Packets may traval through N1 via different routing path, in which 
*  case the packets may arrive at Firewall out of the order that they 
*  are injected into N1.  
*  There is a possibility that a packet with FIN set arrives prior to 
*  a packet that was sent before the FIN-packet. Note that Firewall 
*  does not maintain segments of TCP connections. Thus, there is no way 
*  for Firewall to identify whether a packet arrives out of order or not. 
*  This weakness leads disorder of TCP connection state transference.  
*  Firewall considers a tcp connection will be torn down after receiving 
*  FINs and thus tear down the corresponding state entry immediately. 
*  However, there may be data packets in the flight.  
*
****/

#include <click/element.hh>
#include <click/timer.hh>
#include <stdint.h>
#include <clicknet/tcp.h>

CLICK_DECLS
// Uncomment to enable debug information printed.
// #define DEBUGTIMER_ACTIVE 1 


// cycle to flush debug information, in milliseconds. 
const uint32_t debug_flush_cycle = 1000;
enum action{ DROP, ALLOW };
// fw_state defines 8 states of stateful firewall.  
enum fw_state{ CLOSE, SYN_1, SYN_2, ESTABLISHED, FIN_1, FIN_2, CLOSING_WAIT, LAST_ACK };
extern const char* readable_state[8];

struct entry{
    unsigned int src_ip;
    unsigned int src_ip_mask;
    unsigned int des_ip;
    unsigned int des_ip_mask;

    uint16_t src_port_min;
    uint16_t src_port_max;
    uint16_t des_port_min;
    uint16_t des_port_max;

    unsigned char protocol;
    enum action action;
    // This is for migration, identifying which record it is. 
    uint16_t seq;

    struct entry* pre;
    struct entry* next;
    
    struct entry* delete_pre;
    struct entry* delete_next;
    struct entry* append_pre;
    struct entry* append_next;
    
    struct state_entry* connection;
    uint32_t active_time;
    // set to 0, not in _delete_ or _append_. 
    // set to 1, in _delete_. 
    // set to 2, in _append_. 
    uint8_t d_a;
};

struct ipchain{
    int size;
    struct entry* head;
    struct entry* tail;
    struct entry* _delete_;
    struct entry* _append_;
    uint32_t _delete_size_;
    uint32_t _append_size_;
    // record how many 'deleted' entries are still active. 
    //
    // When a TCP rule is added to the _delete_ link, don't change the value 
    // of delete_refs. Instead, increase the value of delete_refs by 1, each 
    // time a state_entry is added to the _delete_ link. (state_entry has 
    // it's own _delete_ link.) 
    // In the function 
    //          firewallstate::fs_add_state_to_delete(struct entry*),
    // a set of state_entries associated to the given entry will be detached 
    // from that entry and then append at the front of _delete_ link. 
    // Each appending will yield an increament of delete_refs by 1. 
    // The TCP rule itself does NOT result increament of delete_refs.
    // In the function 
    //          static int add_to_delete(struct ipchain*, struct entry*),
    // you should look at the given entry. If the entry is a TCP rule, 
    // then you don't need to modify the value of delete_refs. You can 
    // increase the value of delete_refs only when the given is NOT a 
    // TCP rule. 
    //
    // If a TCP SYN hits a TCP rule, then it have the potential to 
    // crate a new state_entry. In the function 
    //          firewallstate::add_entry(Packet*,struct entry*,struct entry*),
    // If a new state_entry is created successfully, then you should look 
    // whether the related rule is in _delete_ link. 
    // If it's in, then increase delete_refs by 1.(Don't worry about the newly
    // created state_entry, just mark it as 'active'.) Otherwise, leave 
    // delete_refs aside.
    //
    // If a state_entry is deleted from the _use link, which 
    // means a connection expires, then you should check the related rule. 
    // If the rule is in a '_delete_' link, then decrease delete_refs by 1. 
    // If the rule is not in a '_delete_' link, you don't need to do anything
    // extra. Check function, 
    //          firewallstate::fs_delete_entry(struct state_entry*),
    // for more detail.
    //
    //
    uint32_t delete_refs;
    uint16_t delete_seq;
};

struct state_entry {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    enum fw_state state;
    uint32_t life_time;

    // record first syn seq number;
    uint32_t syn1_ack;
    // record second syn seq number;
    uint32_t syn2_ack;
    // record first fin seq number;
    uint32_t fin1_ack;
    // record second fin seq number;
    uint32_t fin2_ack;

    // links to next/previous connection nodes associated to the same rule. 
    struct state_entry* sib_pre;
    struct state_entry* sib_next;

    // links to next/previous connection nodes in free/use links. 
    struct state_entry* store_pre;
    struct state_entry* store_next;
    struct state_entry* delete_pre;
    struct state_entry* delete_next;
    struct state_entry* suspend_pre;
    struct state_entry* suspend_next;

    // indicats which rule introduce this state. 
    struct entry* rule;

    // If you need a search, then make a traverse of "use" link. 
    // "use" link can be implemented as a binary tree. However, now I don't
    // implement it that way. But it's easy to change into that way. 
    
    // Fro migration. To record which rule, this state belongs to.
    uint16_t seq;
    // 1-active, 0-inactive;
    uint8_t active;

};

void printEntry(const struct entry *);


// initial number of nodes that will be allocated to the firewallstate. 
const uint32_t init_state_size = 65536;
// after established, expiration = tcp_expiration * timer_cycle (36 seconds)
// all states except CLOSE, SYN_1 and SYN_2
const uint32_t tcp_expiration = 9;
// during synchronization, expiration = syn_expiration * timer_cycle (8 seconds)
// SYN_1 and SYN_2. 
const uint32_t syn_expiration = 2;
// frequncy of timer rescheduling.
const uint32_t timer_cycle = 4;

class firewallstate : public Element {
public:
    firewallstate();
    ~firewallstate();

    const char* class_name() const      { return "firewallstate"; }
    const char* port_count() const      { return PORTS_0_0; }

    int initialize(ErrorHandler *errh);

    // All return value: 0-fail, 1 successful.

    // periodically flush timers of all state entries.
    int fs_flush_timers();
    // make an state_entry according to Packet, and append this state_entry
    // to the given entry, a rule table entry.
    int fs_add_entry(Packet*, struct entry*, struct entry*);
    // delete a state_entry from 'use' link and put it into 'free' link. 
    int fs_delete_entry(struct state_entry*);
    // search all states and return a pointer to the entry that matches.
    struct state_entry *fs_check_entry(Packet*) const;

    // update a state entry, according to a given packet. 
    int fs_update_state(Packet*, struct state_entry*);
    inline uint8_t fs_get_flag_by_packet(Packet* p) const;
    // claer all rules
    int fs_clear_states();

    // This function prints the state of a given state entry. 
    void fs_print_state(const struct state_entry*, Packet*, uint8_t) const;
    
    // firewall migration. 
    uint32_t fs_get_deleted_state_count() const { return _deleted_state_count; }
    int fs_add_state_to_delete(struct entry*); 
    int fs_attach_state(struct entry*, struct state_entry*);
    int fs_suspend_state(struct state_entry*);
    int fs_attach_suspend_states(struct entry*);
    struct state_entry* fs_pop_from_deleted_state();
    int fs_update_state_by_tag(Packet*);

private:
    struct state_entry* _free;
    struct state_entry* _use;
    class firewalltable* _fwt;
    uint32_t _deleted_state_count;
    struct state_entry* _delete_;
    // states that arrive but cannot match any rules 
    // will be temporally suspended.
    struct state_entry* _suspend_;
};

// milliseconds
const uint32_t rule_flush_cycle = 1000;
// rule active time = rule_active_time*rule_flush_cycle milliseconds.
const uint32_t rule_active_time = 5;


class firewalltable : public Element {

public:
    firewalltable();
    ~firewalltable();

    const char *class_name() const      { return "firewalltable"; }
    const char *port_count() const      { return PORTS_0_0; }

    int initialize(ErrorHandler*);
    void ft_flush_timers();
    void ft_flush_state_timers();
    // Will be called periodically
    void ft_print_debug();
    void ft_clear_debug();

    bool ft_append_entry(struct entry*);
    bool ft_replace_entry(struct entry*, int index);
    bool ft_insert_entry(struct entry*, int index);
    bool ft_delete_entry(struct entry*);
    bool ft_check_entry(struct entry*);
    enum action ft_match_entry(struct entry*); 
    // This function is for stateful firewall 
    enum action ft_match_entry(struct entry*, Packet*);
    int ft_clear();
    int ft_clear_rules();
    void ft_print();
    struct ipchain* ft_get_ipt() {return ipt;}
    //        void ft_print_entry(unsigned int index);

    int ft_get_size() const { return ipt->size; }
    class firewallstate* get_firewall_states() const { return fws; }
    void set_firewall_states(class firewallstate* new_fws) { fws = new_fws; }

    // stateful firewall migration.
    int ft_add_to_delete(struct entry* victim);
    int ft_update_state_by_tag(Packet*);
    int ft_update_rule_by_tag(Packet*);
    // This function will create new entry. 
    int ft_add_to_append(struct entry*);
    struct entry* ft_return_entry(const struct entry*e, uint8_t);
    uint32_t ft_get_delete_size();
    struct entry* ft_pop_from_delete();
    struct state_entry* ft_pop_from_deleted_state();
    // critical for state migration.
    int ft_attach_state(struct entry*, struct state_entry*);
    // states that cannot match any rules will be suspended until expected rule arrives.
    int ft_suspend_state(struct state_entry*);
    struct entry* ft_find_appended_entry_by_seq(uint16_t);
    // all states associated to the given entry will be detached and appended to the 'state'.
    int ft_add_state_to_delete(struct entry*);
    uint32_t ft_get_deleted_state_count() const { return fws->fs_get_deleted_state_count(); }
    int ft_enforce_append();

    
    // Attributes for debug. 
    uint32_t _DebugID;
    uint32_t _PassTCP;
    uint32_t _PassUDP;
    uint32_t _PassOther;
    uint32_t _DropTCP;
    uint32_t _DropUDP;
    uint32_t _DropOther;
    uint32_t _ActiveTCP;
    // Not used yet.
    uint32_t _ActiveUDP;

private:
    struct ipchain* ipt;
    class firewallstate* fws;
};

CLICK_ENDDECLS
#endif
