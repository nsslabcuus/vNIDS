#ifndef CLICK_NFV_FIREWALL_MATCH_HH
#define CLICK_NFV_FIREWALL_MATCH_HH

#include "initglobal.hh"
#include "firewalltable.hh"

CLICK_DECLS

class firewallmatch : public Element { 

public:
    firewallmatch():ft(g_ft) {}
    ~firewallmatch(){} 

    const char *class_name() const		{ return "firewallmatch"; }
    const char *port_count() const		{ return "2-/2-"; }
    // input 0 and output 0 is PULL, others are PUSH.
    const char *processing() const      { return "hh/hh"; }
    void push(int, Packet*);
    enum action domatch(Packet*); 

private:
    firewalltable* ft;

};



CLICK_ENDDECLS
#endif
