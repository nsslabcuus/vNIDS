define($DNS_MAX_LEN 45)
define($DNS_EXPIRE  60)
define($DNS_THRSHLD 60000)

tcp_or_udp :: IPClassifier (
    tcp,
    udp,
    -)

tcp_classifier :: TCPClassifier()
udp_classifier :: UDPClassifier()

dns_analyzer :: DNSAnalyzer()

FromDevice(eth0) -> SetTimestamp -> CheckIPHeader(14) -> IPReassembler() -> GeneveEncap(opt_len 4) -> tcp_or_udp

tcp_or_udp[0] -> CheckTCPHeader() -> tcp_classifier
tcp_or_udp[1] -> CheckUDPHeader() -> udp_classifier
tcp_or_udp[2] -> Discard

mltstp_lw_detector :: MLTSTP_LW_DETECTOR(expire 100)

tcp_classifier[0] -> [0] mltstp_lw_detector [0] -> HTTPAnalyzer() -> Discard
tcp_classifier[1] -> [1] mltstp_lw_detector [1] -> FTPAnalyzer() -> Discard
tcp_classifier[2] -> [2] mltstp_lw_detector [2] -> SSHAnalyzer() -> Discard

dns_last_checktag :: CheckTags(PTAG_DNS_TUNNEL, PTAG_LAST)

udp_classifier[0] -> DNS_LW_DETECTOR(expire $DNS_EXPIRE, threshold $DNS_THRSHLD, max_len $DNS_MAX_LEN) -> CheckTags(PTAG_DNS_TUNNEL) -> dns_analyzer[0] -> DNS_HW_DETECTOR -> [0]dns_last_checktag[0] -> Discard
dns_analyzer[1] -> [1]dns_last_checktag[1] -> Discard
