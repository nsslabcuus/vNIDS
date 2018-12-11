#include <click/config.h>
#include "tabletimer.hh"

CLICK_DECLS
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

int 
TableTimer::initialize(ErrorHandler *errh) {
    UNUSED(errh);
    _timer.initialize(this);
    _timer.schedule_now();
    return 0;
}

void 
TableTimer::run_timer(Timer *timer) {
    assert(timer == &_timer);
    if ( NULL != g_ft ) {
        g_ft->ft_flush_timers();
    }
    _timer.schedule_after_msec(rule_flush_cycle);
} 

void 
TableTimer::push(int port, Packet* p) {
    UNUSED(port);
    p->kill();
}


CLICK_ENDDECLS
EXPORT_ELEMENT(TableTimer)
