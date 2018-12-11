// -*- c-basic-offset: 4 -*-
/*
 * settimestamp.{cc,hh} -- set timestamp annotations
 * Douglas S. J. De Couto, Eddie Kohler
 * based on setperfcount.{cc,hh}
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2005 Regents of the University of California
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
#include <click/logger.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>

#include "getruntime.hh"

CLICK_DECLS

GetRunTime::GetRunTime() : count(0), pos(0) {}

int GetRunTime::configure(Vector<String>& conf, ErrorHandler* errh) {
  return Args(conf, this, errh).read("position", pos).execute();
}

Packet* GetRunTime::simple_action(Packet* p) {
  if (p == NULL) {
    return NULL;
  }

  count++;

  uint64_t now = Timestamp::now().nsec();

  uint64_t ptime = p->timestamp_anno().nsec();

  LOG_EVAL("position %d count %ld time: now %ld ptime %ld difference %ld\n",
           pos, count, now, ptime, now - ptime);

  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GetRunTime)
