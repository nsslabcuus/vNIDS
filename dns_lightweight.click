// lightweight part

define($DNS_MAX_LEN 20)
define($DNS_EXPIRE  60)
define($DNS_THRSHLD 600)
define($FROM_DEV click_v_1)
define($TO_DEV click_v_1)

mac_filter::Classifier(
12/0800, 
-);

dns_last_checktag :: CheckTags(PTAG_DNS_TUNNEL, PTAG_LAST)

// Add a classifier to filter out the IP packets 
FromDevice($FROM_DEV, OUTBOUND 1) ->mac_filter[0] ->
//Classifier(0/000000000001)[0] -> 
SetTimestamp -> CheckIPHeader(14) -> IPReassembler() -> GeneveEncap(opt_len 4)
-> DNS_LW_DETECTOR(expire $DNS_EXPIRE, threshold $DNS_THRSHLD, max_len $DNS_MAX_LEN)  -> 
CheckTags(PTAG_DNS_TUNNEL)


// strip 66 geneve header
-> Strip(LENGTH 66) -> CheckIPHeader(14) -> EtherRewrite(SRC 00:00:00:00:00:01, DST 00:00:00:00:00:02) -> Queue
-> [0]dns_last_checktag[0] -> Discard

mac_filter[1] -> Discard

