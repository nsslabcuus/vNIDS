#include <click/config.h>
#include <click/logger.h>

#include "checktags.hh"

CLICK_DECLS

#define PTAG_CMD_DEF(cmd) "PTAG_" #cmd,

static const char *ptag_cmd_words[] = {
#include "packet_tags.def"
};

#undef PTAG_CMD_DEF

CheckTags::CheckTags()
    : _tag(PTAG_NONE),
      packet_count(0),
      notag_or_total(0),
      process_us(0),
      _is_last(false),
      _stat_times(0),
      _timer(this) {}

int CheckTags::initialize(ErrorHandler *errh) {
  (void)errh;
  _timer.initialize(this);
  _timer.schedule_after_sec(60 * 30);
  return 0;
}

CheckTags::~CheckTags() { do_statistics(); }

void CheckTags::do_statistics() {
  int avg_int = 0, avg_point = 0;
  if (notag_or_total > 0) {
    int avg10 = (process_us * 100) / notag_or_total;
    avg_int = avg10 / 100;
    avg_point = avg10 % 100;
  }

  if (_is_last) {
#if CLICK_DMALLOC
    click_mem_info();
#endif
    LOG_EVAL("%d\t %s\t %lu\t %lu\t %d.%02d", _stat_times, ptag_cmd_words[_tag],
             process_us, notag_or_total, avg_int, avg_point);
  } else {
    LOG_EVAL("%d\t NONE_%s\t %lu\t %lu\t %d.%02d", _stat_times,
             ptag_cmd_words[_tag], process_us, notag_or_total, avg_int,
             avg_point);
    LOG_EVAL("Total %lu, some packets disappears", packet_count);
  }
  _stat_times++;
}

int CheckTags::configure(Vector<String> &conf, ErrorHandler *errh) {
  (void)errh;
  // only the first String is valid
  if (conf.size() == 0) return 0;
  for (int code = PTAG_NONE + 1; code < PTAG_LAST; code++) {
    if (0 == strcmp(conf[0].c_str(), ptag_cmd_words[code])) {
      _tag = (ptag_t)code;
      break;
    }
  }

  // if conf[1] is PTAG_LAST
  if (conf.size() > 1 &&
      0 == strcmp(conf[1].c_str(), ptag_cmd_words[PTAG_LAST]))
    _is_last = true;
  else
    _is_last = false;
  return 0;
}

void CheckTags::run_timer(Timer *timer) {
  assert(timer == &_timer);
  do_statistics();
  _timer.reschedule_after_sec(60 * 30);
}

Packet *CheckTags::simple_action(Packet *p) {
  ++packet_count;
  if (_is_last) {
    ++notag_or_total;
    Timestamp interval = Timestamp::now() - p->timestamp_anno();
    process_us += interval.usec_per_sec * interval.sec() + interval.usec();
  } else if (!get_tag(p, _tag)) {
    ++notag_or_total;
    Timestamp interval = Timestamp::now() - p->timestamp_anno();
    process_us += interval.usec_per_sec * interval.sec() + interval.usec();
    p->kill();
    return NULL;
    ;
  }
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CheckTags)
