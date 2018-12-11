#ifndef CLICK_INITGLOBAL_HH
#define CLICK_INITGLOBAL_HH
#include <click/element.hh>
#include <click/string.hh>
//#include "singleton.hh"
#include "firewalltable.hh"

CLICK_DECLS

/*
    Init all globals. 
*/

/******************************************************************
Declearation of globals. 
********************************************************************/
extern firewalltable* g_ft;


class Initglobal : public Element { 

public:
    Initglobal() CLICK_COLD;
    const char *class_name() const		{ return "Initglobal"; }
    const char *port_count() const		{ return PORTS_1_1; }
    
    int initialize(ErrorHandler*);
};


CLICK_ENDDECLS
#endif
