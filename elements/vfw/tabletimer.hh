#ifndef CLICK_TABLETIMER_HH
#define CLICK_TABLETIMER_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "initglobal.hh"
#include "firewalltable.hh"

CLICK_DECLS

// TagDetector will turn into inactive if 
// there is no more tagged packet observed within ACTIVE_TIME. 
#define ACTIVE_TIME 30

class TableTimer : public Element { 
public:

    TableTimer(): _timer(this) {}
    ~TableTimer() {}

    int initialize(ErrorHandler *errh);
    void run_timer(Timer *timer);

    const char *class_name() const		{ return "TableTimer"; }
    const char *port_count() const		{ return "1/0"; }
    const char *processing() const      { return "a"; }
    void push(int, Packet*);
    

private:
    Timer _timer;
};

CLICK_ENDDECLS
#endif
