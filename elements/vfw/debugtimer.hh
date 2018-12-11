#ifndef CLICK_DEBUGTIMER_HH
#define CLICK_DEBUGTIMER_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "initglobal.hh"
#include "firewalltable.hh"


CLICK_DECLS

// This element is used for debug. 
// This element will print debug info periodically. 


class DebugTimer : public Element { 
public:

    DebugTimer(): _timer(this) {}
    ~DebugTimer() {}

    int initialize(ErrorHandler *errh);
    void run_timer(Timer *timer);

    const char *class_name() const		{ return "DebugTimer"; }
    const char *port_count() const		{ return "1/0"; }
    const char *processing() const      { return "a"; }
    void push(int, Packet*);
    

private:
    Timer _timer;
};

CLICK_ENDDECLS
#endif
