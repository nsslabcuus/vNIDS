#ifndef CLICK_TAGDETECTOR_HH
#define CLICK_TAGDETECTOR_HH

#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

// TagDetector will turn into inactive if 
// there is no more tagged packet observed within ACTIVE_TIME. 
#define ACTIVE_TIME 30

class TagDetector : public Element { 
public:

    TagDetector():_timer(this),_active(0),_packet_count(0) {}
    ~TagDetector() {}

    int initialize(ErrorHandler *errh);
    void run_timer(Timer *timer);

    const char *class_name() const		{ return "TagDetector"; }
    const char *port_count() const		{ return "2-/1-"; }
    const char *processing() const      { return "hh/h"; }
    void push(int, Packet*);
    

private:
    Timer _timer;
    // If set, TagDetector will let tagged packet pass. 
    uint8_t _active;
    unsigned long _packet_count;
};

CLICK_ENDDECLS
#endif
