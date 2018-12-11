#ifndef CLICK_NFV_FWMANAGER_HH
#define CLICK_NFV_FWMANAGER_HH
#include <click/element.hh>
#include <click/timer.hh>
#include "firewalltable.hh"
#include "initglobal.hh"

CLICK_DECLS

enum fwman_state{NORMAL, P_APPEND, P_DELETE, P_APPEND_END, P_DELETE_END};
extern const char* readable_fm_state[5];

/***
 *  Here we define an extentional entry structure.
 *  This structure will be used to store multiple rules. 
 *  This structure will be used in fwmanager element. 
 *
 *  Onece the element received a packet, then it will pasre the packet 
 *  and extracts the contents. The contetns in the packet will be the 
 *  commands and the rules. 
 *
 *  One packet might carry multipule rules.
 *  
 *  The packet carrying rules are sent from Dom0, which is considered as 
 *  the orchestration. So there should be a program that sends packets 
 *  running on Dom0. 
 *
 ***/
 struct exentry {
    int length;                 // Total length of the exentry (bytes)
    int elength;                // Length of entries (bytes)
    int entry_num;              // Number of entries 
    struct entry entry[0];      // Start of entries.  
     /* There may padding here. */
};

struct exstate_entry {
    int length;                 // Total length of the exstate_entry (bytes)
    int elength;                // Length of entries (bytes)
    int entry_num;              // Number of entries
    struct state_entry entry[0];      // Start of entries. 
    /*  There may padding here. */
};


/**
 *  This is the class of firewall.
 *  This class take resposibility for filtering the packets that
 *  are passed to it.
 *
 **/
// check delete_ref every 50 milliseconds.
const uint32_t delete_ref_check_cycle = 50;

class fwmanager : public Element { 

public:
    fwmanager();
    ~fwmanager(){} 

    const char *class_name() const		{ return "fwmanager"; }
    /* one input, one output*/
    const char *port_count() const		{ return "2-/4-"; }
    const char *processing() const      { return "hh/hhhh"; }
    // 'push' action will automatically call simple_action.
    // Packet *simple_action(Packet *);
    void push(int, Packet*);

    int initialize(ErrorHandler *);
    void run_timer(Timer*);
    int fm_check_delete_refs();

    bool fm_append_entry(struct exentry*);
    bool fm_replace_entry(struct exentry*, uint16_t* indexes); 
    bool fm_insert_entry(struct exentry*, uint16_t* indexes);
    bool fm_delete_entry(struct exentry*);
    bool fm_check_entry(struct exentry*);
    // called directly from push.  
    int fm_demultiplex_from_peer(int, Packet*);
    int fm_demultiplex_from_controller(int, Packet*);
    int fm_takeAction(uint8_t, uint8_t, struct exentry*, uint16_t* indexes); 

    // stateful firewall migration. 
    int fm_packet_to_exentry(struct exentry*&, uint16_t*&, Packet*, uint8_t*);
    int fm_packet_to_exentry(struct exentry*&, Packet*, uint8_t*);
    int fm_add_entry_to_exentry(struct exentry*, int, const struct entry*);
    int fm_add_to_delete(struct exentry*);  // add all entries in exentry to _delete_
    int fm_add_to_append(struct exentry*);  // add all entries in exentry to _append_
    int fm_enforce_delete();
    int fm_enforce_append();
    // This functions is critical. 
    WritablePacket* fm_exentry_to_packet(const struct exentry*, uint8_t, uint8_t, uint8_t);
    
    int fm_send_states();
    int fm_add_state_to_exstate(struct exstate_entry*, int, struct state_entry*);
    WritablePacket* fm_exstate_to_packet(const struct exstate_entry*, uint8_t, uint8_t, uint8_t);
    int fm_packet_to_exstate(struct exstate_entry*&, Packet*, uint8_t*);
    // critical for states installation.
    int fm_attach_state(struct exstate_entry*);
    struct entry* fm_find_appended_entry_by_seq(uint16_t);
    // all states associated with the given exentry, will be detached and appended to the 'states'. 
    int fm_add_states_to_delete(struct exentry*);
    
    // after fwmanager receives a 'p_append_end' message from peer, it calls this function. 
    int fm_send_activation();
    // after fwmanager receives a 'p_delete' message from controller, 
    // or after fwmanager sends a 'p_append_end' to the other peer.
    int fm_notify_detector(bool);
    // after fm_enforce_delete() is called. 
    // send out a 'p_append_end' message indicating completion. 
    int fm_send_p_append_end();
    // make an network packet. I.e., IP packet. 
    // with ip_heaer() set and check sum set.
    // with `data` as its content. 
    WritablePacket* make_network_packet(const uint8_t* data, uint32_t, uint8_t);
    // make an ethernet packet from a network packet.
    WritablePacket* make_ether_packet(Packet*, uint8_t*);
    // send a message to the controller when it's ready.
    int fm_notify_controller();
    int fm_clear();
    void fm_print();


private:
    firewalltable* ft;
    enum fwman_state _state;
    Timer _timer;
    // peer's MAC address. 
    uint8_t ether_dhost[6];
    // controller's MAC. Used when notify controller.
    uint8_t controller_dhost[6];
};

CLICK_ENDDECLS
#endif
