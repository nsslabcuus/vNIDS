#include <click/config.h>
#include "statetimer.hh"

CLICK_DECLS

#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

int 
StateTimer::initialize(ErrorHandler *errh) {
    UNUSED(errh);
    _timer.initialize(this);
    _timer.schedule_now();
    return 0;
}

void 
StateTimer::run_timer(Timer *timer) {
    assert(timer == &_timer);
    if ( NULL != g_ft ) {
        g_ft->ft_flush_state_timers();
    }
    _timer.schedule_after_sec(timer_cycle);
} 

void 
StateTimer::push(int port, Packet* p) {
    UNUSED(port);
    p->kill();
}


CLICK_ENDDECLS
EXPORT_ELEMENT(StateTimer)
