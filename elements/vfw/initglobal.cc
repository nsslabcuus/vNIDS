/*
 * print.{cc,hh} -- element prints packet contents to system log
 * John Jannotti, Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2008 Regents of the University of California
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "initglobal.hh"

CLICK_DECLS
#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

/* definition of global variables. */
firewalltable *g_ft;


Initglobal::Initglobal()
{
    g_ft = new firewalltable();
    // create firewall state table. 
    class firewallstate *tmp_fws = new firewallstate();
    // set firewall state table. 
    g_ft->set_firewall_states(tmp_fws);
}

int
Initglobal::initialize(ErrorHandler *errh) {
    UNUSED(errh);
    return 0;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Initglobal)
ELEMENT_MT_SAFE(Initglobal)
