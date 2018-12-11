#include <click/config.h>
#include "debugtimer.hh"

CLICK_DECLS
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

int 
DebugTimer::initialize(ErrorHandler *errh) {
    _timer.initialize(this); 
    UNUSED(errh);
#ifdef DEBUGTIMER_ACTIVE
    _timer.schedule_now();
#endif
    return 0;
}

void 
DebugTimer::run_timer(Timer *timer) {
    assert(timer == &_timer);
    if ( NULL != g_ft ) {
        g_ft->ft_print_debug();
    }
    _timer.schedule_after_msec(debug_flush_cycle);
} 

void 
DebugTimer::push(int port, Packet* p) {
    UNUSED(port);
    p->kill();
}


CLICK_ENDDECLS
EXPORT_ELEMENT(DebugTimer)
