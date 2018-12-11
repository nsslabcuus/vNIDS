// lightweight part

define($DNS_MAX_LEN 20)
define($DNS_EXPIRE  60)
define($DNS_THRSHLD 600)
define($FROM_DEV click_v_peer_1)
define($TO_DEV click_v_peer_1)

tcp_or_udp :: IPClassifier (
    tcp,
    udp,
    -)

tcp_classifier :: TCPClassifier()
udp_classifier :: UDPClassifier()

// Add a classifier to filter out the packets that send to $FROM_DEV
FromDevice($FROM_DEV) -> Classifier(0/000000000001)[0] -> SetTimestamp -> CheckIPHeader(14) -> IPReassembler() -> GeneveEncap(opt_len 4) -> tcp_or_udp

tcp_or_udp[0] -> CheckTCPHeader() -> tcp_classifier
tcp_or_udp[1] -> CheckUDPHeader() -> udp_classifier
tcp_or_udp[2] -> Discard

mltstp_lw_detector :: MLTSTP_LW_DETECTOR(expire 100)

dns_last_checktag :: CheckTags(PTAG_DNS_TUNNEL, PTAG_LAST)

tcp_classifier[0] -> [0] mltstp_lw_detector [0] -> HTTPAnalyzer() -> Discard
tcp_classifier[1] -> [1] mltstp_lw_detector [1] -> FTPAnalyzer() -> Discard
tcp_classifier[2] -> [2] mltstp_lw_detector [2] -> SSHAnalyzer() -> Discard

// Break after CheckTags(PTAG_DNS_TUNNEL) to make two click configurations that each runs as one instance. First part is lightweight, the second part is heavyweight
// Strip the geneve header then send to ToDevice. Notice: the geneve header is 
//    uint32_t size = 14 + sizeof(click_udp) + sizeof(click_ip) + sizeof(click_geneve) + _opt_len*4; // see the implementation of GeneveEncap. The size will change along with _opt_len in GeneveEncap configuration.
// Since click configuration is non-turing-complete language. You should calculate the size by hand then configure the Strip element with the size.
// 	size = 14 + 8 + 20 + 8 + 4*4 = 66

udp_classifier[0] -> DNS_LW_DETECTOR(expire $DNS_EXPIRE, threshold $DNS_THRSHLD, max_len $DNS_MAX_LEN) -> CheckTags(PTAG_DNS_TUNNEL)
// strip 66 geneve header
-> Strip(LENGTH 66) -> CheckIPHeader(14) -> EtherRewrite(SRC 00:00:00:00:00:01, DST 00:00:00:00:00:02) -> Queue
-> [0]dns_last_checktag[0] -> ToDevice($TO_DEV)


