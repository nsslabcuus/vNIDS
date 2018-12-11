#ifndef CLICK_VIDS_HEAVYWEIGHT_HH
#define CLICK_VIDS_HEAVYWEIGHT_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c

SetTimestamp([TIMESTAMP, I<keyword> FIRST])

=s timestamps

store the time in the packet's timestamp annotation

=d

Store the specified TIMESTAMP in the packet's timestamp annotation. If
TIMESTAMP is not specified, then sets the annotation to the system time when
the packet arrived at the SetTimestamp element.

Keyword arguments are:

=over 8

=item FIRST

Boolean.  If true, then set the packet's "first timestamp" annotation, not its
timestamp annotation.  Default is false.

=back

=a StoreTimestamp, AdjustTimestamp, SetTimestampDelta, PrintOld */

class HeavyWeight : public Element {
 public:
  HeavyWeight() CLICK_COLD;

  const char *class_name() const { return "HeavyWeight"; }
  const char *port_count() const { return PORTS_1_1; }
  int configure(Vector<String> &, ErrorHandler *);
  Packet *simple_action(Packet *);

 private:
  int size;
};

CLICK_ENDDECLS
#endif
