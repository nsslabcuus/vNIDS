#include <click/config.h>
#include "tagdetector.hh"

CLICK_DECLS
//#define TAGDETECTOR_DEBUG_ON 1
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

int 
TagDetector::initialize(ErrorHandler *errh) {
    UNUSED(errh);
    _timer.initialize(this);
    // schedule it right now.
    _timer.schedule_now();
    return 0;
}

void 
TagDetector::run_timer(Timer *timer) {
  UNUSED(timer);
#ifdef TAGDETECTOR_DEBUG_ON
    fprintf(stdout, "TagDetector timeouts!\n");
    fprintf(stdout, "Buffer consumed: %ld\n", _packet_count);
    fflush(stdout);
#endif
    _packet_count = 0;
    _active = 0;
} 

/***
 *  TagDetector should be connected like this: 
 *  
 *  port 0 receives tagged packets if there are any. 
 *  (from classified traffic) -> [0]TagDetector;
 *  
 *  port 1 receives message from fwmanager. 
 *  fwmanager[0] -> [1]TagDetector;
 *
 *  the only output is to firewall match element, delivering tagged packets.
 *  TagDetector[0] -> [1]FirewallMatch;
 *
 **/
void 
TagDetector::push(int port, Packet* p) {
    // It's tagged traffic.
    if ( likely(0 == port) ) {
        if ( 0 != _active ) {
            _packet_count++;
            checked_output_push(0, p);
        } else {
            p->kill();
        }
    // It's from fwmanager.
    } else if ( 1 == port ) {

        switch ( p->ip_header()->ip_p ) {
            // Turn on. 
            case 0xfe : {
                _active = 1;
#ifdef TAGDETECTOR_DEBUG_ON
                fprintf(stdout, "TagDetector on!\n");
                fflush(stdout);
#endif
                // set _active to 0 after 30 seconds.
                _timer.schedule_after_sec(ACTIVE_TIME);
                break;
            }
            // Turn off. 
            case 0xfd : {
                _active = 0; 
                fprintf(stdout, "Buffer consumed: %ld\n", _packet_count);
                _packet_count = 0;
#ifdef TAGDETECTOR_DEBUG_ON
                fprintf(stdout, "TagDetector off!\n");
                fflush(stdout);
#endif
                break;
            }
            default: {
                fprintf(stderr, "[warn] TagDetector: Receive message from fwmanager that can't parse!\n");
                fflush(stderr);
            }
        }
        p->kill();
    }
}


CLICK_ENDDECLS
EXPORT_ELEMENT(TagDetector)
