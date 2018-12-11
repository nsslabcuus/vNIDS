#include <click/config.h>
#include <click/logger.h>
#include <clicknet/tcp.h>
#include "tcpclassifier.hh"
CLICK_DECLS

TCPClassifier::TCPClassifier() {}

int TCPClassifier::configure(Vector<String> &conf, ErrorHandler *errh) {
  (void)conf;
  (void)errh;
  // @todo configuration
  return 0;
}

void TCPClassifier::push(int port, Packet *p) {
  (void)port;
  Packet *np = reassemble(p);
  if (np) {
    classify(np);
  }
}

/** @todo: determine if need to reassemble tcp packets
 */
Packet *TCPClassifier::reassemble(Packet *p) { return p; }

/** @brief
 * classify if HTTP, FTP, SSH <br/>
 * simply by port <br/>
 * @todo classify by analyzing application protocol header in the future
 */
void TCPClassifier::classify(Packet *p) {
  const click_tcp *tcp = p->tcp_header();
  uint32_t th_sport = ntohs(tcp->th_sport);
  uint32_t th_dport = ntohs(tcp->th_dport);
  // @note Assume that the smaller port indicates the protocol
  uint32_t small_port = th_sport <= th_dport ? th_sport : th_dport;

  LOG_DEBUG("port %d -> %d : len %u", th_sport, th_dport, p->length());

#define HTTP_OUT_PORT 0
#define FTP_OUT_PORT 1
#define SSH_OUT_PORT 2
  if (80 == small_port) {
    output(HTTP_OUT_PORT).push(p);
  } else if (20 == small_port) {
    output(FTP_OUT_PORT).push(p);
  } else if (22 == small_port) {
    output(SSH_OUT_PORT).push(p);
  } else {
    p->kill();
  }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(TCPClassifier)
