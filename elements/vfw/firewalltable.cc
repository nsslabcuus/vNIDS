#include <click/config.h>
#include <stdio.h>
#include <stdlib.h>
#include "firewalltable.hh"

CLICK_DECLS

#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)
// comment this out when release. 
#define FIREWALLTABLE_EVAL 1
//#define FIREWALLSTATE_EVAL 1

extern class firewalltable* g_ft;
const char* readable_state[8] = {
    "CLOSE___", 
    "SYN_1___", 
    "SYN_2___", 
    "EST_____", 
    "FIN_1___", 
    "FIN_2___", 
    "CLOSE_W_", 
    "LAST_ACK" 
};

/*******************************************************************/
// Definition of functions of ipchain. 
//
int getChainSize(const struct ipchain* c)
{
	return c->size;
}

struct entry* allocEntry()
{
	entry *e = new entry();
    if ( NULL == e ) {
        fprintf(stderr, "[fetal] allocEntry: out of memory!\n");
        fflush(stderr);
        while (1);
    }
    e->delete_pre = NULL;
    e->delete_next = NULL;
    e->append_pre = NULL;
    e->append_next = NULL;
    e->connection = NULL;
    e->d_a = 0;
    e->seq = 0;
    e->active_time = 0;
	return e;
}
/**
 *  It's very dangerous to invoke this function 
 *  When the first parameter, e1, is in the real 
 *  firewall table. 
 *
 *  overwrite e1, with e2 directly and without any 
 *  other initialization is dangerous. 
 *  
 *  USE THIS FUNCTION AT YOUR OWN RISTK. 
 *
 **/
bool copyEntry(struct entry* e1, const struct entry* e2)
{
	if (!(e1 && e2))
		return false;
	e1->src_ip = e2->src_ip;
	e1->src_ip_mask = e2->src_ip_mask;
	e1->des_ip = e2->des_ip;
	e1->des_ip_mask = e2->des_ip_mask;
	e1->src_port_min = e2->src_port_min;
	e1->src_port_max = e2->src_port_max;
	e1->des_port_min = e2->des_port_min;
	e1->des_port_max = e2->des_port_max;

	e1->protocol = e2->protocol;
	e1->action = e2->action;
	
    return true;
}

struct ipchain* allocChain()
{
	ipchain *c = new ipchain();
	struct entry* head = allocEntry();
	struct entry* tail = allocEntry();

	head->pre = NULL;
	head->next = tail;

	tail->pre = head;
	tail->next = NULL;

	c->head = head;
	c->tail = tail;
	c->size = 0;
    c->_delete_ = NULL;
    c->_delete_size_ = 0;
    c->_append_ = NULL;
    c->_append_size_ = 0;
    c->delete_refs = 0;
    c->delete_seq = 0;
	return c;
}


struct entry* getEntryByIndex(const struct ipchain* c, int index)
{
	// improve: can make a bit optimization!
	if (index > c->size - 1)
	{
		printf("ERROR: Index is out of bound");
		return NULL;
	}

	struct entry *cur = c->head->next;

	while(cur) {
		if (index == 0)
			return cur;
		else{
			cur = cur->next;
			index--;
		}
	}

	return NULL;
}

void printEntry(const struct entry* e) 
{
	printf("-------------------------------------------------------------\n");
    printf("source ip          : %u\n", ntohl(e->src_ip));
    printf("source ip mask     : %u\n", ntohl(e->src_ip_mask));
    printf("destination ip     : %u\n", ntohl(e->des_ip));
    printf("destination ip mask: %u\n", ntohl(e->des_ip_mask));
    printf("srouce port        : %hu - %hu\n", e->src_port_min, e->src_port_max);
    printf("destination port   : %hu - %hu\n", e->des_port_min, e->des_port_max);
    printf("protocol           : %hhu\n", e->protocol);
    printf("action             : %d\n", int(e->action));
    printf("-------------------------------------------------------------\n");
}

static bool addEntryAtTail(struct ipchain* c, struct entry* e)
{
    if (!(c && e)) {
		return false;
    }
	struct entry* tmp = c->tail->pre;
    e->next = c->tail;
    e->pre = tmp;
	tmp->next = e;
	c->tail->pre = e;
	c->size++;
    return true;
}


bool addEntryAtHead(struct ipchain* c, struct entry* e)
{
    if (!(c && e))
		return false;

	struct entry* tmp = c->head->next;
	e->next = tmp;
	e->pre = c->head;
	tmp->pre = e;
	c->head->next = e;
	c->size++;

    return true;
}


bool delEntryByIndex(struct ipchain* c, int index)
{
	if (!c)
		return false;

	if (index > c->size - 1)
	{
		printf("ERROR: Index is out of bound");
		return false;
	}

	struct entry* tmp = getEntryByIndex(c, index);
	tmp->pre->next = tmp->next;
	tmp->next->pre = tmp->pre;
	free(tmp);
    c->size--;
	return true;
}

void printChain(const struct ipchain* c) {

	struct entry* en = c->head->next;
	while(en->next) {
		printEntry(en);
		en = en->next;
	}
}

inline struct entry* nextEntry(const struct ipchain* c, const struct entry* e){
	UNUSED(c);
    return e->next;
}

inline bool isEntryEqual(const struct ipchain* c, const struct entry* e1, const struct entry* e2){
	UNUSED(c);
    if (e1->src_ip == e2->src_ip &&
		e1->src_ip_mask == e2->src_ip_mask &&
		e1->des_ip == e2->des_ip &&
		e1->des_ip_mask == e2->des_ip_mask &&
		e1->src_port_min == e2->src_port_min &&
		e1->src_port_max == e2->src_port_max &&
		e1->des_port_min == e2->des_port_min &&
		e1->des_port_max == e2->des_port_max &&
		e1->protocol == e2->protocol &&
		e1->action == e2->action)
		return true;
	else
		return false;
}

/**
 *  This function receives three parameters. 
 *
 *  c   :   ipchain. 
 *  e1  :   rule entry that will be matched against. 
 *  e2  :   entry generated from a packet. 
 *
 *  e2 will be compared with e1. e1 is one of the rule entries that is in the given ipchain, c. 
 *  If e2 can matche e1, then returns `true`, otherwise returns `false`.
 *
 *  e1 can be a wildcard rule entry.
 *  e2 must be a specific rule entry, no wildcard is allowed for e2.
 *
 **/
inline bool isEntryMatch(const struct ipchain* c, const struct entry* e1, const struct entry* e2){
	//check port
    UNUSED(c);
	if (e2->src_port_min < e1->src_port_min ||
		e2->src_port_max > e1->src_port_max ||
		e2->des_port_min < e1->des_port_min ||
		e2->des_port_max > e1->des_port_max)
		return false;
	
    //check ip address is or not matched
	if (ntohl(e2->des_ip) < ntohl(e1->des_ip) || (ntohl(e2->des_ip) > ntohl(e1->des_ip | e1->des_ip_mask)) ||
	    ntohl(e2->src_ip) < ntohl(e1->src_ip) || (ntohl(e2->src_ip) > ntohl(e1->src_ip | e1->src_ip_mask)))
        return false;


	// check protocol
	if (e1->protocol != e2->protocol)
		return false;
	
	return true;
}

// for stateful firewall migration.
/**
 *  Add the given entry to _delete_, set delete_refs and _delete_size_ correspondingly
 *  return 
 *      0-fail, 
 *      1-successful.
 * */
static int add_to_delete(struct ipchain* c, struct entry* e) {
    e->delete_pre = NULL;
    e->delete_next = c->_delete_;
    if ( NULL != c->_delete_ ) {
        c->_delete_->delete_pre = e;
    }
    c->_delete_ = e;
    c->_delete_size_++;
    // It's not TCP and it's currently active. 
    if ( 0x06 != e->protocol && NULL != e->connection ) {
        c->delete_refs++;
    }
    e->d_a = 1;
    c->delete_seq++;
    e->seq = c->delete_seq;
    return 1;   
}

static inline uint32_t get_delete_size(const struct ipchain* c) {
    return c->_delete_size_; 
}
static inline uint16_t get_delete_seq(const struct ipchain* c) {
    return c->delete_seq;
}
/**
 *  return 
 *      NULL - not found. 
 *      pointer to the entry - found. 
 ***/
static struct entry* find_appended_entry_by_seq(struct ipchain* c, uint16_t seq) {
    struct entry* ret = c->_append_;
    if ( NULL != ret ) {
        while ( NULL != ret->append_next ) {
            // found it.
            if ( seq == ret->seq ) {
                return ret;
            } else {
                ret = ret->append_next;
            }
        }
        if ( seq == ret->seq ) {
            return ret;
        }
    }
    return NULL;
}

/**
 *  Pop the head of the _delete_ link. 
 *  And detach all pointer connections from ipchain. 
 *
 *  return: 
 *      NULL-link is empty
 *      point to entry - successful.
 * */
static struct entry* pop_from_delete(struct ipchain* c) {
    struct entry* ret = NULL;
    if ( c->_delete_size_ > 0 && NULL != c->_delete_) {
        // pop from _delete_. 
        ret = c->_delete_;
        c->_delete_ = ret->delete_next;
        ret->delete_next = NULL;
        ret->delete_pre = NULL;
        if ( NULL != c->_delete_ ) {
            c->_delete_->delete_pre = NULL;
        }
        c->_delete_size_--;
        // pop from ipchain. 
        ret->pre->next = ret->next;
        ret->next->pre = ret->pre;
        c->size--;
        ret->next = NULL;
        ret->pre = NULL;
    }
    return ret;
}


/**
 *  Append the given entry at the head of _append_ link. 
 *  Also, append the given entry at the end of ipchain. 
 *
 *  return 
 *      0 - fail. 
 *      otherwise - successful. 
 **/
static int add_to_append(struct ipchain* c, struct entry* e) {
    // append at the tail of c->_append_;
    e->append_pre = NULL;
    e->append_next = c->_append_;
    if ( NULL != c->_append_ ) {
        c->_append_->append_pre = e;
    }
    c->_append_ = e;
    c->_append_size_++;
    // append at the end of ipchain. 
    if ( addEntryAtTail(c, e) != false ) {
        return 1;
    } else {
        return 0;
    }
}


/*******************************************************************/
// Definition of class firewallstate. 
//
firewallstate::firewallstate():
    _free(NULL),
    _use(NULL),
    // Note, firewallstate should be initiated after firewalltable. 
    _fwt(g_ft),
    _deleted_state_count(0),
    _delete_(NULL),
    _suspend_(NULL)
{
    int index = 0;
    struct state_entry* tmp;
    while ( index < (int)init_state_size ) {
        tmp = new state_entry();
        tmp->sib_pre = NULL;
        tmp->sib_next = NULL;
        tmp->rule = NULL;
        // append at the head of free link. 
        tmp->store_pre = NULL;
        tmp->store_next = _free;
        if ( NULL != _free ) {
            _free->store_pre = tmp;
        }
        _free = tmp;
        index++;
    }
}

firewallstate::~firewallstate() 
{
    struct state_entry* tmp;
    struct state_entry* kill;
    tmp = _use;
    while ( NULL != tmp ) {
        kill = tmp;
        tmp = tmp->store_next;
        delete kill;
    }
    tmp = _free;
    while ( NULL != tmp ) {
        kill = tmp;
        tmp = tmp->store_next;
        delete kill;
    }
}
/***
 *  This function add the given entry's all states to the _delete_
 *  link. Other properties of the states remain the same.  
 *  Also, the ipt->delete_refs will be increased appropriately.
 *
 *  return 
 *      0 - fail. 
 *      1 - successful.
 ***/
int 
firewallstate::fs_add_state_to_delete(struct entry* e) {
    if ( NULL != e->connection ) {
        struct ipchain* c = _fwt->ft_get_ipt();
        struct state_entry *last = e->connection;
        // append all states to _delete_
        while ( NULL != last ) {
            last->seq = e->seq;
            last->delete_pre = NULL;
            last->delete_next = _delete_;
            if ( NULL != _delete_ ) {
                _delete_->delete_pre = last;
            }
            _delete_ = last;
            _deleted_state_count++;
            // update delete_refs
            if ( 0 != last->active ) {
                c->delete_refs++;
            }
            last = last->sib_next;
        }
    }
    return 1;
}

/**
 *  Once the fwmanager receives a tagged packet, fwmanager may 
 *  call this functions if the packet is TCP. 
 *  This functions will update 
 *  `delete_refs`
 *
 *  return 
 *      0 - fail. 
 *      1 - successful.
 ***/
int 
firewallstate::fs_update_state_by_tag(Packet* p) {
    const struct click_ip *iph = p->ip_header();
    const struct click_tcp *thd = p->tcp_header();
    uint32_t src_ip = (uint32_t)(iph->ip_src.s_addr);
    uint32_t dst_ip = (uint32_t)(iph->ip_dst.s_addr);
    uint16_t src_port = ntohs(thd->th_sport);
    uint16_t dst_port = ntohs(thd->th_dport);
    struct state_entry* s;
    s = _delete_;
    while ( NULL != s ) {
        if ( ((src_ip == s->src_ip)&&
              (dst_ip == s->dst_ip)&&
              (src_port == s->src_port)&&
              (dst_port == s->dst_port)) || 
             ((src_ip == s->dst_ip)&&
              (dst_ip == s->src_ip)&&
              (src_port == s->src_port)&&
              (dst_port == s->dst_port)) || 
             ((src_ip == s->src_ip)&&
              (dst_ip == s->dst_ip)&&
              (src_port == s->dst_port)&&
              (dst_port == s->src_port)) || 
             ((src_ip == s->dst_ip)&&
              (dst_ip == s->src_ip)&&
              (src_port == s->dst_port)&&
              (dst_port == s->src_port))
           ) {
            // If the matched state is active, then turn it off
            // and decrease delete_refs.
            if ( 0 != s->active ) {
                s->active = 0;
                _fwt->ft_get_ipt()->delete_refs--;
                return 1;
            }
        }
        s = s->sib_next;
    }
    return 1;
}


/***
 *  This function returns the first state_entry from the _delete_ link. 
 *  And set the pointers appropriately.
 *  
 *  return 
 *      NULL    -   fail. 
 *      pointer to state_entry - successful.
 *
 ****/
struct state_entry* 
firewallstate::fs_pop_from_deleted_state() {
    struct state_entry* ret = _delete_;
    // pop from _delete_ link. 
    if ( 0 == _deleted_state_count || NULL == _delete_ ) {
        return NULL;  
    }
    _delete_ = ret->sib_next;
    ret->sib_next = NULL;
    if ( NULL != _delete_ ) {
        _delete_->sib_pre = NULL;
    } 
    // pop from _use link. 
    if ( NULL != ret->store_pre ) {
        ret->store_pre->store_next = ret->store_next;
    } else {
        _use = ret->store_next;
    }
    if ( NULL != ret->store_next ) {
        ret->store_next->store_pre = ret->store_pre;
    }
    return ret;
}

int
firewallstate::initialize(ErrorHandler * errh) {
    UNUSED(errh);
    return 0;
}

int 
firewallstate::fs_flush_timers() {
    // update timers in each state entry and delete if necessarry.
    struct state_entry* tmp;
    struct state_entry* kill;
    int ret = 1;
    tmp = _use;
    while ( NULL != tmp ) {
        tmp->life_time--;
        if ( static_cast<signed int>(tmp->life_time) <= 0 ) {
            kill = tmp;
            tmp = tmp->store_next;
            kill->state = CLOSE;
            ret = fs_delete_entry(kill);
#ifdef FIREWALLSTATE_EVAL  
            fs_print_state(kill, NULL, 2);
#endif 
        } else {
            tmp = tmp->store_next;
        }
    }
    return ret;
}

inline uint8_t 
firewallstate::fs_get_flag_by_packet(Packet* p) const {
    return static_cast<uint8_t>((p->tcp_header())->th_flags);
}


/***
 *  This function updates the state of a given state entry, 
 *  according to the given packet, including life_time. 
 *  
 *  If it's a valid, legitimate packet, then update the entry. 
 *  However, if it fails to update the entry (e.g., due to lack
 *  of memory), then this function may return 0. In this failed 
 *  case, the packet should be denied. 
 *
 *  If the given packet is not a legitimate or valid packet, 
 *  this function will return 0. In this failed case, the packet 
 *  should be denied. 
 *
 *  In summary, if this function returns 0, which means failure, 
 *  then the caller should interpreter it as 'deny' this packet. 
 *
 *  Input: 
 *      p   :   the packet to check against. 
 *      s   :   the state entry to be updated. 
 *  
 ***/
int
firewallstate::fs_update_state(Packet* p, struct state_entry* s) {
    // get tcp header pointer.  
    const struct click_tcp* thd = p->tcp_header();
    // look packet's flags. 
    uint8_t th_flags = thd->th_flags;
    // return value. default as successful.
    int ret = 1;
    // mask should be: 00010111
    uint8_t mask = (TH_FIN) | (TH_SYN) | (TH_ACK) | (TH_RST);
    
    switch ( th_flags & mask ) {
        // fin. 
        case 0x01: {
            // check. 
            if ( s->state == ESTABLISHED  ) {
                s->fin1_ack = ntohl(thd->th_seq);
                s->state = FIN_1;
                s->life_time = tcp_expiration;
            } else if ( s->state == FIN_1 ) {
                s->fin2_ack = ntohl(thd->th_seq);
                s->state = FIN_2;
                s->life_time = tcp_expiration;
            } else if ( s->state == CLOSING_WAIT ) {
                s->fin2_ack = ntohl(thd->th_seq); 
                s->state = LAST_ACK;
                s->life_time = syn_expiration;
            } else {
                // invalid fin. 
                ret = 0;
            }
            break;
        }
        // syn. 
        case 0x02: {
            // check. 
            if ( s->state == CLOSE ) {
                s->syn1_ack = ntohl(thd->th_seq);
                s->state = SYN_1;
                s->life_time = syn_expiration;
            } else {
                // invalid syn. 
                ret = 0;
            }
            break;
        }
        // ack. 
        case 0x10: {
            // check. 
            if ( s->state == ESTABLISHED ) {
                // pass this packet. 
                s->life_time = tcp_expiration;
            } else if ( s->state == SYN_2 && (ntohl(thd->th_ack) == s->syn2_ack+1) ) {
                s->state = ESTABLISHED;
                s->life_time = tcp_expiration;
            } else if ( s->state == FIN_1 ) {
                // This ack is for the first FIN.  
                if ( ntohl(thd->th_ack) == s->fin1_ack+1 ) {
                    s->state = CLOSING_WAIT;
                    s->life_time = tcp_expiration;
                }
            } else if ( s->state == FIN_2 ) {
                // This ack is for the second FIN. 
                if ( ntohl(thd->th_ack) == s->fin2_ack+1 ) {
                    s->state = LAST_ACK;
                    s->life_time = syn_expiration;
                }
            } else if ( s->state == LAST_ACK && (ntohl(thd->th_ack) == s->fin2_ack+1) ) {
                s->state = CLOSE;
                ret = fs_delete_entry(s);
            } else {
                // invalid ack. 
                ret = 0;
            }
            break;
        }
        // fin + ack 
        case 0x11: {
            // check. 
            if ( s->state == ESTABLISHED ) {
                s->fin1_ack = ntohl(thd->th_seq);
                s->state = FIN_1;
                s->life_time = tcp_expiration;
            } else if ( s->state == FIN_1 ) { 
                // reply to the previous fin. 
                if ( ntohl(thd->th_ack) == s->syn1_ack+1 ) {
                    s->state = LAST_ACK;
                    s->life_time = syn_expiration;
                // this ack reply to other data segments, not previous fin. 
                } else {
                    s->state = FIN_2; 
                    s->life_time = tcp_expiration;
                }
                s->fin2_ack = ntohl(thd->th_seq);
            // this case, ack must reply to a data segment. 
            } else if ( s->state == CLOSING_WAIT ) {
                s->state = LAST_ACK;
                s->fin2_ack = ntohl(thd->th_seq);
                s->life_time = syn_expiration;
            } else {
                // invalid fin + ack.
                ret = 0;
            }
            break;
        }
        // syn + ack 
        case 0x12: {
            // check. 
            if ( s->state == SYN_1 && (ntohl(thd->th_ack) == s->syn1_ack+1)) {
                s->syn2_ack = ntohl(thd->th_seq);
                s->state = SYN_2;
                s->life_time = syn_expiration;
            } else {
                // invalid syn+ack. 
                ret = 0;
            }
            break;
        }
        // rst (+ack)
        case 0x14: case 0x04: {
            // check. 
            s->state = CLOSE;
            // should delete this node.
            ret = fs_delete_entry(s);
            // reset this connection. 
            break;
        }
        // None of the above. 
        default: {
            // invalid tcp flag.  
            ret = 0;
        }
    }

    //
    // Here I print the latest state. 
    // Although, the state entry may have been 'deleted',
    // the content is still valid. 
    // If it's in multi-core context, this should be adjusted appropriately. 
    //
#ifdef FIREWALLSTATE_EVAL
    if ( ret > 0 ) {
        fs_print_state(s, p, 0);
    } else {
        fs_print_state(s, p, 1);
    }
#endif
    return ret;
}


/**
 *  This function adds a new state entry. 
 *  The new state entry is appended at the front of the link of 
 *  a given firewall rule (specified by parameter rule).
 *
 *  Only tcp syn packet can trigger this function. 
 *
 *  If it's not a valid syn, then fs_update_state(), which is called by this 
 *  function, will return a failure. The failure will prevent the state 
 *  entry from being appended to the 'use' link. Instead, the state entry will 
 *  be appended back to the 'free' link. 
 *
 *  p   :   raw packet. 
 *  e   :   entry that derives from p. 
 *  rule:   which rule introduce this state. 
 *
 **/
int 
firewallstate::fs_add_entry(Packet* p, struct entry* e, struct entry* rule) {
    struct state_entry *tmp = NULL; 
    // If free is not empty, grab a node from 'free'
    if ( NULL != _free ) {
        tmp = _free;
        _free = _free->store_next;
        if ( NULL != _free ) {
            _free->store_pre = NULL;
        }
    // free is empty. 
    } else {
        tmp = new state_entry(); 
        if ( NULL == tmp ) {
            fprintf(stderr, "Could not allocate state entry: out of memory!\n");
            fflush(stderr);
            return 0;
        }
    }
    // fill up new state node. 
    tmp->src_ip = e->src_ip;
    tmp->dst_ip = e->des_ip;
    tmp->src_port = e->src_port_min;
    tmp->dst_port = e->des_port_min;
    tmp->protocol = e->protocol;
    // initial state is set to CLOSE
    tmp->state = CLOSE;
    // Try to update the state of this state entry. 
    int ret = fs_update_state(p, tmp); 
    // If updated successfully. 
    if ( 0 != ret ) {
        // mark this state_entry as active. 
        tmp->active = 1;    
#ifdef DEBUGTIMER_ACTIVE 
        _fwt->_ActiveTCP++;
#endif
        // append to 'use'
        tmp->store_pre = NULL;
        tmp->store_next = _use;
        if ( NULL != _use ) {
            _use->store_pre = tmp;
        }
        _use = tmp;
        // append to 'rule'
        tmp->rule = rule;
        tmp->sib_pre = NULL;
        tmp->sib_next = rule->connection;
        if ( NULL != rule->connection ) {
            rule->connection->sib_pre = tmp;
        }
        rule->connection = tmp;
        // if this rule is in '_delete_' link, 
        // add to _delete_, increase 'delete_refs'.
        if ( 1 == rule->d_a ) {
            tmp->delete_pre = NULL;
            tmp->delete_next = _delete_;
            if ( NULL != _delete_ ) {
                _delete_->delete_pre = tmp;
            }
            _delete_ = tmp;
            _deleted_state_count++;
            _fwt->ft_get_ipt()->delete_refs++; 
        }
    // Otherwise, append it back to 'free'
    } else {
        tmp->active = 0;
        // append it to 'free' link. 
        tmp->rule = NULL;
        tmp->sib_pre = NULL;
        tmp->sib_next = NULL;
        tmp->store_pre = NULL;
        tmp->store_next = _free;
        tmp->delete_pre = NULL;
        tmp->delete_next = NULL;
        if ( NULL != _free ) {
            _free->store_pre = tmp;
        }
        _free = tmp; 
    }
    return ret;
}

/**
 *  Delete a given state entry. 
 *  Delete from 'use' link and append to the head of 'free' link. 
 *  
 *  This function can be called by:
 *  'fs_update_state'. fs_update_state can delete a state entry
 *  due to the closure/reset of a connection. 
 *
 *  s   :   state entry to be deleted. 
 *
 * */
int
firewallstate::fs_delete_entry(struct state_entry* s) {
    // This node is not in use or an error may occur to this node,
    // It's illegal that a state entry is associated to none of the rules. 
    if ( NULL == s->rule ) {
        return 0;
    }
    // if it's the first node. update rule->connection. 
    if ( NULL == s->sib_pre ) {
        s->rule->connection = s->sib_next;
    // else it's not first node. update its previous node. 
    } else {
        s->sib_pre->sib_next = s->sib_next;
    }
    // if it's not the last node. update its next node. 
    if ( NULL != s->sib_next ) {
        s->sib_next->sib_pre = s->sib_pre;
    }
    // garuantee it move clear from rule links.    
    s->sib_pre = s->sib_next = NULL;

    // if it's the first one, the update _use. 
    if ( NULL == s->store_pre ) {
        _use = s->store_next;
    // else it's not the first one. update its previous node. 
    } else {
        s->store_pre->store_next = s->store_next;
    }
    // if it's not the last one, update its next node. 
    if ( NULL != s->store_next ) {
        s->store_next->store_pre = s->store_pre;
    }

    // If the related TCP rule is in '_delete_' link. 
    // decrease delete_refs by 1. 
    if ( 1 == s->rule->d_a ) {
        // remove from _delete_
        if ( NULL != s->delete_pre ) {
            s->delete_pre->delete_next = s->delete_next;
        } else {
            _delete_ = s->delete_next;
        }
        if ( NULL != s->delete_next ) {
            s->delete_next->delete_pre = s->delete_pre;
        }
        s->delete_next = s->delete_pre = NULL;
        _deleted_state_count--;
        if ( 0 != s->active ) {
            _fwt->ft_get_ipt()->delete_refs--;
        }
    }
    s->rule = NULL;
        
    // append it to 'free' link. 
    s->store_pre = NULL;
    s->store_next = _free;
    if ( NULL != _free ) {
        _free->store_pre = s;
    }
    _free = s; 

#ifdef DEBUGTIMER_ACTIVE 
    _fwt->_ActiveTCP--;
#endif
    return 1;
}
/**
 *  Clear all states in _use link. 
 *
 *  This functions uncondictinally delete all states. 
 *
 *
 *  return 
 *      0 - if any one fails.
 *      1 - successful.
 ***/
int 
firewallstate::fs_clear_states() {
    int ret = 1; 
    struct state_entry* tmp = _use;
    while ( NULL != tmp ) {
        ret &= fs_delete_entry(tmp);
        tmp = _use;
    }
    return ret;
}



/**
 *  This function checks whether there is a state entry that 
 *  matches the given packet. 
 *  If the state entry exists, then return a pointer to that entry. 
 *  Otherwise, return NULL.
 *
 ***/
struct state_entry*
firewallstate::fs_check_entry(Packet* p) const {
    const struct click_ip *iph = p->ip_header();
    const struct click_tcp *thd = p->tcp_header();
    uint32_t src_ip = (uint32_t)(iph->ip_src.s_addr);
    uint32_t dst_ip = (uint32_t)(iph->ip_dst.s_addr);
    uint16_t src_port = (uint16_t)ntohs(thd->th_sport);
    uint16_t dst_port = (uint16_t)ntohs(thd->th_dport);
    struct state_entry* s;
    s = _use;
    while ( NULL != s ) {
#if 1
        if ( ((src_ip == s->src_ip)&& 
              (dst_ip == s->dst_ip)&&
              (src_port == s->src_port)&&
              (dst_port == s->dst_port)) || 
             ((src_ip == s->dst_ip)&& 
              (dst_ip == s->src_ip)&&
              (src_port == s->src_port)&&
              (dst_port == s->dst_port)) || 
             ((src_ip == s->src_ip)&& 
              (dst_ip == s->dst_ip)&&
              (src_port == s->dst_port)&&
              (dst_port == s->src_port)) || 
             ((src_ip == s->dst_ip)&& 
              (dst_ip == s->src_ip)&&
              (src_port == s->dst_port)&&
              (dst_port == s->src_port))
           ) {
               // found it. 
               return s;
           }
#endif 
#if 0
        if ( src_ip == s->src_ip ) {
            if ( dst_ip == s->dst_ip ) {
                if ( src_port == s->src_port ) {
                    if ( dst_port == s->dst_port ) {
                        // found;
                        return s;
                    }
                } else if ( dst_port == s->src_port ) {
                    if ( src_port == s-> dst_port ) {
                        // found; 
                        return s;
                    }
                }
            }
        } else if ( dst_ip == s->src_ip ) {
            if ( src_ip == s->dst_ip ) {
                if ( src_port == s->src_port ) {
                    if ( dst_port == s->dst_port ) {
                        // found;
                        return s;
                    }
                } else if ( dst_port == s->src_port ) {
                    if ( src_port == s-> dst_port ) {
                        // found; 
                        return s;
                    }
                }
            }
        }
#endif 
        s = s->store_next;
    }
    return NULL;
}


struct entry*
firewalltable::ft_find_appended_entry_by_seq(uint16_t seq) {
    return find_appended_entry_by_seq(ipt, seq);
}

/**
 *  return:
 *      0 - fail.
 *      1 - successful.
****/
int 
firewallstate::fs_suspend_state(struct state_entry* state) {
    // grab a chunk of memory
    struct state_entry* s;
    if ( NULL != _free ) {
        s = _free;
        _free = _free->store_next;
    } else {
        s = (struct state_entry*)(CLICK_LALLOC(sizeof(struct state_entry)));
    }
    
    // fill up the memory. -- costly.
    memcpy(s, state, sizeof(struct state_entry));
    s->store_next = s->store_pre = NULL;
    
    // append to _suspend_.
    if ( NULL == _suspend_ ) {
        state->suspend_pre = NULL;
        state->suspend_next = NULL;
        _suspend_ = state;
        return 1;
    }
    struct state_entry* tmp = _suspend_;
    while ( NULL != tmp->suspend_next ) {
        // suspend in ascending order.
        if ( s->seq > tmp->seq ) {
            tmp = tmp->suspend_next;
        } else {
            s->suspend_next = tmp;
            s->suspend_pre = tmp->suspend_pre;
            if ( NULL != tmp->suspend_pre ) {
                tmp->suspend_pre->suspend_next = s;
            }
            tmp->suspend_pre = s;
            return 1;
        }
    }
    if ( s->seq > tmp->seq ) {
        s->suspend_pre = tmp;
        s->suspend_next = tmp->suspend_next;
        tmp->suspend_next = s;
        return 1;
    } else {
        s->suspend_next = tmp;
        s->suspend_pre = tmp->suspend_pre;
        if ( NULL != tmp->suspend_pre ) {
            tmp->suspend_pre->suspend_next = s;
        }
        tmp->suspend_pre = s;
        return 1;
    }
}

/**
 *  This function will attach the suspended states 
 *  to the given entry. 
 *  Those states have the same seq with the given entry. 
 *  
 *  return 
 *      0 - fail. 
 *      1 - successful.
 *
****/
int
firewallstate::fs_attach_suspend_states(struct entry* e) {
    if ( NULL == _suspend_ ) {
        return 1;
    }
    struct state_entry* state = _suspend_;
    while ( NULL != state ) {
        if ( e->seq < state->seq ) {
            state = state->suspend_next;
        } else if ( state->seq == e->seq ) {
            // append state to e->connection
            state->sib_next = e->connection;
            if ( NULL != e->connection ) {
                e->connection->sib_pre = state;
            }
            state->sib_pre = NULL;
            e->connection = state; 
            // append state to _use.
            state->store_next = _use;
            if ( NULL != _use ) {
                _use->store_pre = state;
            }
            state->store_pre = NULL;
            _use = state;
            // teardown from _suspend_.
            if ( NULL != state->suspend_pre ) {
                state->suspend_pre->suspend_next = state->suspend_next;
            }
            if ( NULL != state->suspend_next ) {
                state->suspend_next->suspend_pre = state->suspend_pre;
            }
            // set to active. 
            state->active = 0x01;
            state->seq = 0;
            // move to the next
            state = state->suspend_next;
        } else {
            return 1;
        }
    } 
    return 1;
}

/**
 *  This function attach the given state_entry to the given entry. 
 *  And set: 1) storage management, and 2) state management appropriately. 
 *  After calling this function, the state_entry is ready. 
 *  That is to say, the state_entry is ready to work, if there is traffic 
 *  coming.
 *  
 *  e   :   given entry that the state_entry will be attached to. 
 *  s   :   given state_entry that will attach to the given entry. 
 * 
 *  return 
 *      0 - fail. 
 *      1 - successful.
 ***/
int 
firewallstate::fs_attach_state(struct entry* e, struct state_entry* s) {
    struct state_entry *tmp = NULL; 
    // can grab from _free?
    if ( NULL != _free ) {
        tmp = _free;
        _free = _free->store_next;
        if ( NULL != _free ) {
            _free->store_pre = NULL;
        }
    // can't grab from _free, allocate it yourself. 
    } else {
        tmp = new state_entry();
        if ( NULL == tmp ) {
            fprintf(stderr, "Could not allocate state entry: out of memory!\n");
            fflush(stderr);
            while (1);
        }
    }
    // fill up new state node. 
    memcpy(tmp, s, sizeof(state_entry));
    // append to _use. storage management.
    tmp->store_pre = NULL;
    tmp->store_next = _use;
    if ( NULL != _use ) {
        _use->store_pre = tmp;
    }
    _use = tmp;
    // append to 'e', state management.  
    tmp->rule = e;
    tmp->sib_pre = NULL;
    tmp->sib_next = e->connection;
    if ( NULL != e->connection ) {
        e->connection->sib_pre = tmp;
    }
    // set to active. 
    tmp->active = 0x01;
    tmp->seq = 0;
    return 1;
}

/**
 *  This function prints out the given state entry. 
 *  The main purpose of this function is for debugging. 
 *  When the traffic rate is high, the output of this print function 
 *  might make little sense. 
 *  --------------------------------------------------------------
 *  When employ this function in debugging, it is recommended to 
 *  make the traffic rate low enough, e.g., 10 packets per second. 
 *  --------------------------------------------------------------
 *
 *  s       :   pointer to the given state entry that will be printed. 
 *  p       :   pointer to the given packet that might potentially just trigger
 *              an update of state. 
 *  purpose :   0 - update failure, 1 - update success, 2 - none purpose. 
 * 
 *  The format of the print looks like: 
 *  
 *  192.168.1.1:1024 - 192.168.1.2:80 [SYN_1___] (s) [120+0]:[-] [-s--]
 *  192.168.1.2:80 - 192.168.1.1:1024 [SYN_2___] (s) [200+0]:[121] [-sa-]
 *  192.168.1.1:1024 - 192.168.1.2:80 [EST_____] (s) [121+1024]:[201] [--a-]
 *  192.168.1.1:1024 - 192.168.1.2:80 [FIN_1___] (s) [1146+10]:[201] [--af]
 *
 *  192.168.1.2:80 - 192.168.1.1:1024 [CLOSE_W_] (s) [201+0]:[1157] [--a-] 
 *  192.168.1.2:80 - 192.168.1.1:1024 [LAST_ACK] (s) [202+0]:[1157] [--af]
 *  192.168.1.1:1024 - 192.168.1.1:80 [CLOSE___] (s) [1157+0]:[203] [--a-]
 *
 *  Characters in the parentheses can be one of the following:
 *  s, f or -.
 *  (s) represents this packet's has successfully updated the state 
 *      entry's state. purpose=0. 
 *  (f) represents this packet's has failed to update the state entry's state.
 *      purpose=1.
 *  (-) represents no packet trigger this print, it's called by other reasons. 
 *      purpose=2.
 * 
 *  The first column indicates the packet's source ip.
 *  The second column indicates whether it's a packet. (since this function may be
 *  called by other reasons other than packet's trigger.)
 *  The third column indicates the packet's destination ip. 
 *  The fourth column indicates the state after the packet's update. 
 *  The fith column indicates whether this packet successully update. 
 *  The sixth column indicates [seq+len]:[ack_seq] 
 *  The seventh column indicates flags of the pacekts: [reset, syn, ack, fin]
 *
 *
 *  Note, for other reasons other than a packet's trigger, the second column 
 *  could be '+', which means the addresses are not a real packet's. Instead, 
 *  those ip/port addresses are observed from the state entry record. 
 *  If the second column indicates '-', then the addresses come from a real 
 *  packet that trigger an update which then calls this print function to print out 
 *  the latest state. 
 *
 *  If Pakcket is NULL, then the sixth and seventh column will not present. 
 *
 ***/
void 
firewallstate::fs_print_state(const struct state_entry* s, 
                              Packet *p = NULL, 
                              uint8_t purpose = 2 ) const 
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    // Called by other reason. 
    if ( NULL == p ) {
        src_ip = static_cast<uint32_t>(ntohl(s->src_ip));
        dst_ip = static_cast<uint32_t>(ntohl(s->dst_ip));
        src_port = s->src_port;
        dst_port = s->dst_port;
        printf("%hhu.%hhu.%hhu.%hhu:%hu + %hhu.%hhu.%hhu.%hhu:%hu [%s] (-)\n",
                static_cast<uint8_t>((src_ip>>24) & 0x0ff),
                static_cast<uint8_t>((src_ip>>16) & 0x0ff),
                static_cast<uint8_t>((src_ip>> 8) & 0x0ff),
                static_cast<uint8_t>(src_ip       & 0x0ff), src_port,
                static_cast<uint8_t>((dst_ip>>24) & 0x0ff),
                static_cast<uint8_t>((dst_ip>>16) & 0x0ff),
                static_cast<uint8_t>((dst_ip>> 8) & 0x0ff),
                static_cast<uint8_t>(dst_ip       & 0x0ff), dst_port,
                readable_state[static_cast<int>(s->state)] 
              );
    } else {
        const struct click_ip *iph = p->ip_header();
        const struct click_tcp *thd = p->tcp_header();
        src_ip = static_cast<uint32_t>(ntohl(iph->ip_src.s_addr)); 
        dst_ip = static_cast<uint32_t>(ntohl(iph->ip_dst.s_addr)); 
        src_port = static_cast<uint16_t>(ntohs(thd->th_sport));
        dst_port = static_cast<uint16_t>(ntohs(thd->th_dport));
        uint32_t seq = static_cast<uint32_t>(ntohl(thd->th_seq));
        uint32_t ack = static_cast<uint32_t>(ntohl(thd->th_ack));
        printf("%hhu.%hhu.%hhu.%hhu:%hu - %hhu.%hhu.%hhu.%hhu:%hu [%s] (%s) <%u>:<%u>\n",
                static_cast<uint8_t>((src_ip>>24) & 0x0ff),
                static_cast<uint8_t>((src_ip>>16) & 0x0ff),
                static_cast<uint8_t>((src_ip>> 8) & 0x0ff),
                static_cast<uint8_t>(src_ip       & 0x0ff), src_port,
                static_cast<uint8_t>((dst_ip>>24) & 0x0ff),
                static_cast<uint8_t>((dst_ip>>16) & 0x0ff),
                static_cast<uint8_t>((dst_ip>> 8) & 0x0ff),
                static_cast<uint8_t>(dst_ip       & 0x0ff), dst_port,
                readable_state[static_cast<int>(s->state)],
                (0 == purpose) ? ("s") : (1==purpose ? "f" : "-"),
                seq, ack);
    }
}


/*******************************************************************/
// Definition of class firewalltable. 
//
firewalltable::firewalltable():
    _DebugID(0),_PassTCP(0), _PassUDP(0), _PassOther(0),
    _DropTCP(0), _DropUDP(0),_DropOther(0), _ActiveTCP(0), _ActiveUDP(0),
    ipt(allocChain())
{
    if ( NULL == ipt ) {
        fprintf(stderr, "[fetal] firewalltable: initialization failed! (ipt==NULL)\n");
        fflush(stderr);
        while(1);
    }
    // Note, firewallstate is not initiated here. 
    fws = NULL;
}

firewalltable::~firewalltable()
{	
	struct entry* tmp = ipt->head->next;
	while(tmp){
		free(tmp->pre);
		tmp = tmp->next;
	}

	free(ipt->tail);
	free(ipt);
}

bool 
firewalltable::ft_append_entry(struct entry* e_in)
{
    if ( NULL != e_in )
    {
    	struct entry* e = allocEntry();
        if (!copyEntry(e, e_in)) {
    		return false;
        }
    	return addEntryAtTail(ipt, e);
    }	
    else
    {
        printf("ERROR: Entry is NULL!");
        return false;
    }
}


bool 
firewalltable::ft_replace_entry(struct entry* e_in, int index)
{
	if (!e_in)
		return false;

	if (index > ipt->size - 1)
	{
		printf("ERROR: Index is out of bound");
		return false;
	}

	struct entry* e = allocEntry();
	if (!copyEntry(e, e_in))
		return false;

	struct entry* tmp = getEntryByIndex(ipt, index);	
	e->pre = tmp->pre;
	e->next = tmp->next;

	e->pre->next = e;
	e->next->pre = e;
	free(tmp);
	return true;
}

bool 
firewalltable::ft_insert_entry(struct entry* e_in, int index)
{
	if (!e_in)
		return false;

	if (index > ipt->size - 1)
	{
		printf("ERROR: Index is out of bound");
		return false;
	}

	struct entry* e = allocEntry();
	if (!copyEntry(e, e_in))
		return false;

	struct entry* tmp = getEntryByIndex(ipt, index);
	e->pre = tmp->pre;
	e->next = tmp;
	tmp->pre = e;
	e->pre->next = e;
	ipt->size++;

	return true;
}

/***
 *  This function receives an entry. 
 *  ft_delete_entry() first search against the rule table to find 
 *  an exactly same rule with the given entry. 
 *
 *  `exactly same`  means IP addresses, PORTs, protocol and action are 
 *  all identical. 
 *
 *  Then ft_delete_entry() deletes the rule from the rule table 
 *  Finally, ft_delete_entry() free the memory.
 *
 ***/
bool 
firewalltable::ft_delete_entry(struct entry* e)
{
	struct entry* tmp = ipt->head->next;

	while(tmp->next)
	{
		if (isEntryEqual(ipt, e, tmp))
		{
			tmp->pre->next = tmp->next;
			tmp->next->pre = tmp->pre;
			free(tmp);
			ipt->size--;
			return true;
		}

		tmp = tmp->next;
	}

	return false;
}


/**
 *  This functions is similar to ft_match_entry(), except that 
 *  ft_check_entry() returns a boolean value indicating whether 
 *  the given entry matches a particular rule in the rule table. 
 *
 *  ft_match_entry() returns an action (ALLOW/DENY) when the given 
 *  entry matches a particular rule in the rule table. 
 *  If the given entry does not match any of the rules in the rule table, 
 *  then ft_match_entry() will return DENY.
 *
 ***/
bool 
firewalltable::ft_check_entry(struct entry* e)
{
	struct entry* tmp = ipt->head->next;
	while(tmp->next)
	{
		if (isEntryMatch(ipt, tmp, e))
			return true;

		tmp = tmp->next;
	}
	return false;
}


/***
 *  This function matches a given entry against the firewall rules. 
 *  It's for stateless firewall. 
 *  
 *  The input is an entry pointer. 
 *  This given entry is made from packet that is going to be tested whether to dropped or not.
 *
 *  This function invoke "isEntryMatch()", which consider wildcard matching.
 *  That is to say, the given entry may not exactly matches a particular rule in the 
 *  firewall table. But the given entry may hit a rule with wildcard.
 *
 ***/
enum action 
firewalltable::ft_match_entry(struct entry* e)
{
	enum action ret = DROP;
	struct entry* tmp = ipt->head->next;
	while(tmp->next)
	{
        if (isEntryMatch(ipt, tmp, e)) {
            // If it's ICMP/UDP, then set it to active. 
            if ( 1 == tmp->protocol || 17 == tmp->protocol ) {
                tmp->connection = (struct state_entry*)(0x01);
                tmp->active_time = rule_active_time;
            }
            return tmp->action;
        }
		tmp = tmp->next;
	}
	return ret;
}

/***
 *  This function matches a given entry against the firewall rules. 
 *  It's for stateful firewall. 
 ***/
enum action 
firewalltable::ft_match_entry(struct entry* e, Packet* p)
{
    uint8_t flags = fws->fs_get_flag_by_packet(p);
    // If it does not contain ONLY syn, then drop it. 
    if ( (0x00 == (TH_SYN & flags)) || (0x00 != (~(TH_SYN) & flags)) ) {
        return DROP;
    } 

    // Otherwise, might seek to add a new entry. 
	enum action ret = DROP;
    int result = 0;
	struct entry* tmp = ipt->head->next;
	while(tmp->next)
	{
        // Hit a match in the rule table.  
        if ( isEntryMatch(ipt, tmp, e) ) {
            // If this packet is accpeted.
            if ( DROP != tmp->action ) {
                // craete a new state entry.  
                result = fws->fs_add_entry(p, e, tmp);
                // If it fails to crate a new state entry. 
                if ( 0 == result ) {
                    return DROP;
                // Otherwise return whatever action except DROP.
                } else {
                    return tmp->action;
                }
            // Otherwise, not accpeted.
            } else {
                return DROP;
            }
        }
		tmp = tmp->next;
	}
    // If no hit, then return DROP. 
	return ret;
}
/**
 *  This functions clears all the rules and states. 
 *  First clear all states. 
 *  Then clear all rules. 
 ***/
int 
firewalltable::ft_clear()
{
    int ret = 1;
    // clear all states 
    ret &= fws->fs_clear_states(); 
    if ( 0 == ret ) {
        fprintf(stderr, "[error] firewalltable: Could not clear states.\n");
        fflush(stderr);
        return 0;
    } 
    ret &= ft_clear_rules();
    if ( 0 == ret ) {
        fprintf(stderr, "[error] firewalltable: Could not clear rules\n");
        fflush(stderr);
        return 0;
    }
    ipt->delete_refs = 0;
    ipt->_delete_ = NULL;
    ipt->_append_ = NULL;
    ipt->_delete_size_ = 0;
    ipt->_append_size_ = 0;
    ipt->delete_seq = 0;
    return 1;
}

int 
firewalltable::ft_clear_rules() {
    // then clear all rules. 
	struct entry* tmp;
	while(ipt->head->next != ipt->tail){
		tmp = ipt->head->next;
		ipt->head->next = tmp->next;
		tmp->next->pre = ipt->head;
		free(tmp);
	}
	ipt->size = 0;
    return 1;
}


void 
firewalltable::ft_print ()
{
	printChain(ipt);
}

// stateful firewall migration. 
int 
firewalltable::ft_add_to_delete(struct entry* victim) {
    return add_to_delete(ipt, victim);
}

/** 
 *  This function will finally update `delete_refs`
 *
 *  return 
 *      0 - fail. 
 *      1 - successful.
 **/
int 
firewalltable::ft_update_state_by_tag(Packet* p) {
    return fws->fs_update_state_by_tag(p);
}

/** 
 *  This function will finally update `delete_refs`
 *
 *  return 
 *      0 - fail. 
 *      1 - successful.
 **/
int
firewalltable::ft_update_rule_by_tag(Packet* p) {
    const struct click_ip *iph = p->ip_header();
    const uint8_t* pdata = NULL;
    struct entry te;
    te.src_ip = (uint32_t)(iph->ip_src.s_addr);
    te.des_ip = (uint32_t)(iph->ip_dst.s_addr);
    te.src_ip_mask = 0xffffffff;
    te.des_ip_mask = 0xffffffff;
    te.protocol = (uint8_t)(iph->ip_p);
    switch ( te.protocol ) {
        /* ICMP or Pacer */ 
        case 1 : case 252: {
            te.src_port_min = 0;
            te.src_port_max = 0;
            te.des_port_min = 0;
            te.des_port_max = 0;
            break;
        }
        /* UDP */
        case 17: {
            pdata = (uint8_t*)((uint8_t*)iph + (iph->ip_hl << 2));
            te.src_port_min = ntohs(*(uint16_t*)pdata);
            te.src_port_max = te.src_port_min;
            te.des_port_min = ntohs(*(uint16_t*)(pdata+2));
            te.des_port_max = te.des_port_min;
            break;
        }
        /* Other packets */
        default: {
            fprintf(stderr, "protocol: %d\n", te.protocol);
            //fprintf(stderr, "[warn] firewalltable: unexpected TCP!\n"); 
            fflush(stderr);
            return 1;
        } 
    }
    /* ICMP, UDP */
    if ( 1 == te.protocol || 17 == te.protocol ) {
        struct entry* tmp = ipt->_delete_;
        if ( NULL == tmp ) {
#ifdef FIREWALLTABLE_EVAL
            //fprintf(stderr, "[warn] firewalltable: _delete_ is empty while receiving tagged pacekt.\n");
            //fflush(stderr);
#endif
            return 1;
        }
        while ( NULL != tmp ) {
            // found it. 
            if ( isEntryMatch(ipt, tmp, &te) ) {
                // it's active. 
                if ( NULL != tmp->connection ) {
                    // set it to inactive.
                    tmp->connection = NULL;
                    tmp->active_time = 0;
                    ipt->delete_refs--;
                }
                return 1;
            }
            tmp = tmp->delete_next;
        }
#ifdef FIREWALLTABLE_EVAL
        //fprintf(stderr, "[warn] firewalltable: Found tagged packet but not in`delete` link\n");
        //fflush(stderr);
#endif
    /* Pacer */
    } else if ( 252 == te.protocol ) {
        // Set all delete_refs to zero. So, fwmanager::fw_enforce_delete 
        // will be called immediately after current functions returns.
        struct entry* tmp = ipt->_delete_;
        if ( NULL != tmp ) {
            ipt->delete_refs = 0;
        }


    }
    return 1;
}

/** 
 *  return the point of the entry that matches the 
 *  given entry. 
 *  Use "isEntryEqual" to search. That is:
 *      (IP, PORTs, protocol, action) 
 *  must be identical.
 *
 *  tmp->d_a:   if this entry is in _delete_, then tmp->d_a = 1;
 *              if this entry is in _append_, then tmp->d_a = 2;
 *              otherwise, tmp->d_a = 0;
 *  
 *  d_a     :   flag for searching. 
 *              0 - normal search. ignore entry's d_a field. 
 *              1 - search for the first one whose d_a is not set as 1. 
 *              2 - search for the first one whose d_a is not set as 2.
 *              other value - work like 0. 
 *  return  :
 *              returns the reference of te pointer. 
 *              NULL, if there is no matched. 
 * */
struct entry*
firewalltable::ft_return_entry(const struct entry* e, uint8_t d_a = 0) {
    struct entry* tmp = ipt->head->next;
    while( tmp->next ) {
        if ( isEntryEqual(ipt, tmp, e) ) {
            if ( 0 == d_a || d_a != tmp->d_a ) {
                return tmp;
            }
        }
        tmp = tmp->next;
    }
    return NULL;
}

uint32_t
firewalltable::ft_get_delete_size() {
    return get_delete_size(ipt);
}

struct entry*
firewalltable::ft_pop_from_delete() {
    return pop_from_delete(ipt);
}

struct state_entry*
firewalltable::ft_pop_from_deleted_state() {
    return fws->fs_pop_from_deleted_state();
}

int 
firewalltable::ft_add_to_append(struct entry* e_in) {
    if ( NULL != e_in ) {
        struct entry* e = allocEntry();
        e->src_ip = e_in->src_ip;
        e->src_ip_mask = e_in->src_ip_mask;
        e->des_ip = e_in->des_ip;
        e->des_ip_mask = e_in->des_ip_mask;
        e->src_port_min = e_in->src_port_min;
        e->src_port_max = e_in->src_port_max;
        e->des_port_min = e_in->des_port_min;
        e->des_port_max = e_in->des_port_max;
        e->protocol = e_in->protocol;
        e->action = e_in->action;
        e->seq = e_in->seq;
        //e->connection = NULL;
        e->d_a = 2;
        // check whether there exists matching states.
        fws->fs_attach_suspend_states(e);
        return add_to_append(ipt, e);
    } else {
        fprintf(stderr, "[error] firewalltable: entry is NULL!\n");
        fflush(stderr);
        return 0;
    }
}

int 
firewalltable::ft_add_state_to_delete(struct entry* e) {
    return fws->fs_add_state_to_delete(e); 
}


/***
 *  This function finds the appropriate entry from the given 'append' link.  
 *  Then call functions to append the state_entry to the entry that was found. 
 *
 *  return 
 *      0 - fail. 
 *      1 - successful.
 ***/
int 
firewalltable::ft_attach_state(struct entry* e, struct state_entry* s) {
    if ( NULL == e || NULL == s ) {
        return 0;
    }
    struct entry* tmp = e;
    while ( NULL != tmp ) {
        // found it. 
        if ( tmp->seq == s->seq ) {
            return fws->fs_attach_state(tmp, s);
        } else {
            tmp = tmp->append_next;
        }
    }
    return 0;
}

/**
 *  States that cannot match any rules will be suspended until
 *  the expected rule arrives.
 *  return 
 *      0 - fail.
 *      1 - successful.
 ***/
int 
firewalltable::ft_suspend_state(struct state_entry* s) {
    int ret = fws->fs_suspend_state(s);
    return ret;
}


/**
 *  return 
 *      0 - fail. 
 *      1 - successful.
 **/
int 
firewalltable::ft_enforce_append() {
    struct entry* append = ipt->_append_;
    struct entry* last = append;
    if ( NULL == append ) {
        fprintf(stderr, "[warn] firewalltable: _append_ is empty when enforce append.\n");
        fflush(stderr);
    }
    while ( NULL != last ) {
        append = last->append_next;
        last->append_next = NULL;
        last->append_pre = NULL;
        last->d_a = 0;
        last->seq = 0;
        last = append;
    } 
    ipt->_append_ = NULL;
    ipt->_append_size_ = 0;
    return 1;
}

int 
firewalltable::initialize(ErrorHandler *errh) {
    UNUSED(errh);
    return 0;
}

void 
firewalltable::ft_flush_state_timers() {
    if ( NULL != fws ) {
        fws->fs_flush_timers();
    } 
}


void
firewalltable::ft_flush_timers() {
    struct entry* tmp = ipt->head->next;
    while ( NULL != tmp->next ) {
        // not TCP rule. 
        if ( 6 != tmp->protocol ) {
            if ( tmp->active_time > 0 ) {
                tmp->active_time--;
                // If this rule gets timeout. 
                if ( 0 == tmp->active_time ) {
                    // This rule is in _delete_ link.
                    if ( 1 == tmp->d_a ) {
                        tmp->connection = NULL;
                        ipt->delete_refs--; 
                    }
                }
            }
        }
        tmp = tmp->next;
    }
}

// Will be called by the element, DebugTimer periodically. 
// Print any statistics here. 
void
firewalltable::ft_print_debug() {
    fprintf(stdout, "ID, #ActiveTCP, #ActiveUDP, #PassTCP, #PassUDP, #DropTCP, #DropUDP\n"); 
    fprintf(stdout, "%u,%u,%u,%u,%u,%u,%u\n", 
           _DebugID, _ActiveTCP, _ActiveUDP, _PassTCP, _PassUDP, _DropTCP, _DropUDP);
}

// this function will be called whenever CLEARANCE of debug info is required.
void 
firewalltable::ft_clear_debug() {
    _DebugID = _ActiveTCP = _ActiveUDP = _PassTCP = _PassUDP = 
    _PassOther =_DropTCP = _DropUDP = _DropOther = 0;
}



CLICK_ENDDECLS
EXPORT_ELEMENT(firewalltable)
ELEMENT_MT_SAFE(firewalltable)
