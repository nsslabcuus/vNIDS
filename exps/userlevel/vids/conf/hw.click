// heavyweight part
define($FROM_DEV click_v_peer_2)
define($TO_DEV click_v_peer_2)
define($PERFLOW_EXPIRE 300)
dns_analyzer :: DNSAnalyzer()

FromDevice($FROM_DEV) -> Classifier(0/000000000002)[0] -> SetTimestamp -> CheckIPHeader(14) -> PerFlowAnalysis(expire $PERFLOW_EXPIRE) -> IPReassembler()
-> Print
-> CheckUDPHeader() -> dns_analyzer

dns_analyzer[0] -> DNS_HW_DETECTOR -> Discard
dns_analyzer[1] -> Discard
