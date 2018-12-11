// -*- c-basic-offset: 4 -*-
#include <click/config.h>
#include "mergedqueue.hh"
#include <click/args.hh>
#include <click/error.hh>
CLICK_DECLS

MergedQueue::MergedQueue()
    : _q(0), 
    dqcount(0), 
    _active(0), 
    _consumed_length(NULL),
    _packet_count(NULL)
{
}

MergedQueue::~MergedQueue() {
    if ( NULL != _consumed_length ) {
        CLICK_LFREE(_consumed_length, ninputs());
    }
    if ( NULL != _packet_count) {
        CLICK_LFREE(_packet_count, ninputs());
    }
}

void *
MergedQueue::cast(const char *n)
{
    if (strcmp(n, "Storage") == 0)
	return (Storage *)this;
    else if (strcmp(n, "MergedQueue") == 0
	     || strcmp(n, "Queue") == 0)
	return (Element *)this;
    else
	return 0;
}

int
MergedQueue::configure(Vector<String> &conf, ErrorHandler *errh)
{
    unsigned new_capacity = 1000;
    if (Args(conf, this, errh).read_p("CAPACITY", new_capacity).complete() < 0)
	return -1;
    _capacity = new_capacity;
    return 0;
}

int
MergedQueue::initialize(ErrorHandler *errh)
{
    assert(!_q && head() == 0 && tail() == 0);
    _q = (Packet **) CLICK_LALLOC(sizeof(Packet *) * (_capacity + 1));
    if (_q == 0)
	return errh->error("out of memory");
    _drops = 0;
    _highwater_length = 0;
    _consumed_length = (unsigned long*) CLICK_LALLOC(sizeof(unsigned long) * ninputs());
    if ( NULL == _consumed_length ) {
        return errh->error("out of memory for MergedQueue.");
    }
    _packet_count = (unsigned long*) CLICK_LALLOC(sizeof(unsigned long) * ninputs());
    if ( NULL == _packet_count ) {
        return errh->error("out of memory for MergedQueue.");
    }
    for ( int i = 0; i < ninputs(); ++i ) {
        _consumed_length[i] = _packet_count[i] = 0;
    }
    return 0;
}

int
MergedQueue::live_reconfigure(Vector<String> &conf, ErrorHandler *errh)
{
    // change the maximum queue length at runtime
    Storage::index_type old_capacity = _capacity;
    // NB: do not call children!
    if (MergedQueue::configure(conf, errh) < 0)
	return -1;
    if (_capacity == old_capacity || !_q)
	return 0;
    Storage::index_type new_capacity = _capacity;
    _capacity = old_capacity;

    Packet **new_q = (Packet **) CLICK_LALLOC(sizeof(Packet *) * (new_capacity + 1));
    if (new_q == 0)
	return errh->error("out of memory");

    Storage::index_type i, j;
    for (i = head(), j = 0; i != tail() && j != new_capacity; i = next_i(i))
	new_q[j++] = _q[i];
    for (; i != tail(); i = next_i(i))
	_q[i]->kill();

    CLICK_LFREE(_q, sizeof(Packet *) * (_capacity + 1));
    _q = new_q;
    set_head(0);
    set_tail(j);
    _capacity = new_capacity;
    return 0;
}

void
MergedQueue::take_state(Element *e, ErrorHandler *errh)
{
    MergedQueue *q = (MergedQueue *)e->cast("MergedQueue");
    if (!q)
	return;

    if (tail() != head() || head() != 0) {
	errh->error("already have packets enqueued, can%,t take state");
	return;
    }

    set_head(0);
    Storage::index_type i = 0, j = q->head();
    while (i < _capacity && j != q->tail()) {
	_q[i] = q->_q[j];
	i++;
	j = q->next_i(j);
    }
    set_tail(i);
    _highwater_length = size();

    if (j != q->tail())
	errh->warning("some packets lost (old length %d, new capacity %d)",
		      q->size(), _capacity);
    while (j != q->tail()) {
	q->_q[j]->kill();
	j = q->next_i(j);
    }
    q->set_head(0);
    q->set_tail(0);
}

void
MergedQueue::cleanup(CleanupStage)
{
    for (Storage::index_type i = head(); i != tail(); i = next_i(i))
	_q[i]->kill();
    CLICK_LFREE(_q, sizeof(Packet *) * (_capacity + 1));
    _q = 0;
}

void
MergedQueue::push(int port, Packet *p)
{
    _consumed_length[port] += p->length();
    _packet_count[port]++;
    // If you change this code, also change NotifierQueue::push()
    // and FullNoteQueue::push().
    Storage::index_type h = head(), t = tail(), nt = next_i(t);

    // should this stuff be in MergedQueue::enq?
    if (nt != h) {
	    _q[t] = p;
	    //packet_memory_barrier(_q[t], tail());
	    set_tail(nt);
	    int s = size(h, nt);
	    if (s > _highwater_length)
	        _highwater_length = s;
    } else {
        if (_drops == 0 && _capacity > 0) {
            fprintf(stderr,"MergedQueue Overflow!\n");
            fflush(stderr);
        }
	    //click_chatter("%p{element}: overflow", this);
	    _drops++;
	    checked_output_push(1, p);
    }
}

Packet *
MergedQueue::pull(int)
{
#if MERGEDQUEUE_DEBUG_ON
    if ( 0 == _active ) {
        _active = 1;
        for ( int i = 0; i < ninputs(); ++i ) {
            fprintf(stdout, "input[%d] packets:%ld, buffer:%ld\n", 
                    i, _packet_count[i], _consumed_length[i]);
        }
        fflush(stdout);
    }
#endif
    return deq();
}


String
MergedQueue::read_handler(Element *e, void *thunk)
{
    MergedQueue *q = static_cast<MergedQueue *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
      case 0:
	return String(q->size());
      case 1:
	return String(q->highwater_length());
      case 2:
	return String(q->capacity());
      case 3:
	return String(q->_drops);
      default:
	return "";
    }
}

void
MergedQueue::reset()
{
    while (Packet *p = pull(0))
	checked_output_push(1, p);
}

int
MergedQueue::write_handler(const String &, Element *e, void *thunk, ErrorHandler *errh)
{
    MergedQueue *q = static_cast<MergedQueue *>(e);
    int which = reinterpret_cast<intptr_t>(thunk);
    switch (which) {
      case 0:
	q->_drops = 0;
	q->_highwater_length = q->size();
	return 0;
      case 1:
	q->reset();
	return 0;
      default:
	return errh->error("internal error");
    }
}

void
MergedQueue::add_handlers()
{
    add_read_handler("length", read_handler, 0);
    add_read_handler("highwater_length", read_handler, 1);
    add_read_handler("capacity", read_handler, 2, Handler::h_calm);
    add_read_handler("drops", read_handler, 3);
    add_write_handler("capacity", reconfigure_keyword_handler, "0 CAPACITY");
    add_write_handler("reset_counts", write_handler, 0, Handler::h_button | Handler::h_nonexclusive);
    add_write_handler("reset", write_handler, 1, Handler::h_button);
}


CLICK_ENDDECLS
ELEMENT_PROVIDES(Storage)
EXPORT_ELEMENT(MergedQueue)
