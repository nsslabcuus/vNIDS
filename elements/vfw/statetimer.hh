#ifndef CLICK_STATETIMER_HH
#define CLICK_STATETIMER_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "initglobal.hh"
#include "firewalltable.hh"

CLICK_DECLS

// TagDetector will turn into inactive if 
// there is no more tagged packet observed within ACTIVE_TIME. 

class StateTimer : public Element { 
public:

    StateTimer(): _timer(this) {}
    ~StateTimer() {}

    int initialize(ErrorHandler *errh);
    void run_timer(Timer *timer);

    const char *class_name() const		{ return "StateTimer"; }
    const char *port_count() const		{ return "1/0"; }
    const char *processing() const      { return "a"; }
    void push(int, Packet*);
    

private:
    Timer _timer;
};

CLICK_ENDDECLS
#endif
