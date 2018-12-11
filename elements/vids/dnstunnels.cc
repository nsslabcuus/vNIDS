/*
 * DNSTUNNELS.{cc,hh} -- element used to detect dns tunnels attack
 * HHZZK
 *
 * Copyright (c) 2017 HHZZK
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

#include <stdio.h>
//#include <click/args.hh>
#include <click/config.h>
#include <click/logger.h>
#include <clicknet/dns.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/packet_anno.hh>
#include <click/timer.hh>

#include "datamodel.hh"
#include "dnsanalyzer.hh"
#include "dnstunnels.hh"
#include "event.hh"

CLICK_DECLS

#define UNUSED(expr) \
  do {               \
    (void)(expr);    \
  } while (0)

DNSTUNNELS::DNSTUNNELS() {}

DNSTUNNELS::~DNSTUNNELS() {}

int DNSTUNNELS::configure(Vector<String> &conf, ErrorHandler *errh) {
  if (_record_head) return 0;

  UNUSED(conf);
  UNUSED(errh);
  _record_head = (dnstunnels_record *)malloc(sizeof(dnstunnels_record));
  if (!_record_head) return -1;

  _record_head->next = NULL;
  _record_head->count = -1;

  return 0;
}

// Check if the host ip is exists in the record
dnstunnels_record *DNSTUNNELS::check_hostip_exist(uint32_t host_ip) {
  dnstunnels_record *tmp = _record_head;

  while (tmp) {
    if (tmp->host_ip == host_ip) return tmp;
    tmp = tmp->next;
  }

  return NULL;
}

// Use head insert
bool DNSTUNNELS::add_record(uint32_t host_ip, uint32_t create) {
  dnstunnels_record *record = NULL;

  if (!_record_head) return false;

  record = (dnstunnels_record *)malloc(sizeof(dnstunnels_record));
  if (record) {
    record->next = _record_head->next;
    _record_head->next = record;
    record->host_ip = host_ip;
    record->count = 1;
    record->create_time = create;

    return true;
  }

  return false;
}

bool DNSTUNNELS::delete_record(dnstunnels_record *record) {
  dnstunnels_record *pre_record = _record_head;

  while (pre_record->next) {
    if (pre_record->next == record) break;

    pre_record = pre_record->next;
  }

  pre_record->next = record->next;
  free(record);
  record = NULL;

  return true;
}

Packet *DNSTUNNELS::pull(int port) {
  UNUSED(port);
  
  Packet *p = input(0).pull();
  if (p == NULL) {
    return NULL;
  }
  dnstunnels_record *record = NULL;
  event_t *_event = extract_event(p);
  DNSDataModel model(_event->data);
  if (model.validate(_event->data + _event->event_len)) {
    uint32_t ip = get_value<DNSDataModel, DNS_FIELD_RECORD_IP>(model);
    char *qname = get_field<DNSDataModel, DNS_FIELD_QNAME>(model);

    record = check_hostip_exist(ip);
    if (!record) {
      if (add_record(ip, (uint32_t)Timestamp::now().sec())) {
        LOGE("Adding new record success, ip = %u", ip);
      } else {
        LOGE("Adding new record failure, ip = %u", ip);
      }
      return p;
    }
    // Check if the record is expired
    if ((uint32_t)Timestamp::now().sec() - record->create_time >
        DNSTUNNELS_EXPIRATION) {
      delete_record(record);
      LOGE("record deleted!");
      record = NULL;
      return p;
    }

    record->count++;
    if (record->count > COUNT_THRESHOLD) {
      delete_record(record);
      LOGE("Suspicious! record count is %d", record->count);
      return p;
    } else {
      int query_len = strlen(qname);
      int i = 0;
      int num_count = 0;
      LOGE("query len is %d", query_len);
      if (query_len > DNSTUNNELS_QUERY_LEN_THRESHOLD) {
        for (i = 0; i < query_len; i++) {
          if (qname[i] > '0' && qname[i] < '9') num_count++;
        }
      }

      if (num_count * 10 / query_len > PERCENTAGE_OF_COUNT) {
        LOGE("Suspicious! Numberical charicter overload");
        return p;
      }
    }
  } else {
    LOGE("DataModel invalid!");
  }
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DNSTUNNELS)
ELEMENT_MT_SAFE(DNSTUNNELS)
