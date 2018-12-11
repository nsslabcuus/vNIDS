// Definition of virtual devices.
feth0 :: FromDevice(enp0s3);
teth0 :: ToDevice(enp0s3);
//feth1 :: FromDevice(lo);
//teth1 :: ToDevice(lo);
feth1 :: Idle();
teth1 :: Discard(); 
feth2 :: FromDevice(lo);
teth2 :: ToDevice(lo);
// Definition of local addresses. 
define ($eth0_mac 00:00:00:00:01:00);
define ($eth1_mac 00:00:00:00:01:01);
define ($eth2_mac 00:00:00:00:01:02);
define ($eth0_mask 000000000100);
define ($eth1_mask 000000000101);
define ($eth2_mask 000000000102);
// Definition of client and server. 
define ($server_mac 90:e2:ba:a4:7b:c0);
define ($client_mac 90:e2:ba:83:c7:d0);
define ($server_mask 90e2baa47bc0);
define ($client_mask 90e2ba83c7d0);
//-----------------------------------------------------------------------------
// Definition of VNF_IN.
VNF_IN :: {
    //input[0] -> StripEtherVLANHeader(0) -> [0]output; // from eth0 
    //input[1] -> StripEtherVLANHeader(0) -> [1]output; // from eth1
    //input[2] -> StripEtherVLANHeader(0) -> [2]output; // from eth2
    input[0] -> [0]output; // from eth0 
    input[1] -> [1]output; // from eth1
    input[2] -> [2]output; // from eth2
};
feth0 -> [0]VNF_IN;
feth1 -> [1]VNF_IN;
feth2 -> [2]VNF_IN;

// Definition of VNF_OUT. set MAC here. 
VNF_OUT :: {
    input[0]->StoreEtherAddress($eth0_mac,src)->[0]output; // to eth0
    input[1]->StoreEtherAddress($eth1_mac,src)->[1]output; // to eth1
    input[2]->StoreEtherAddress($eth2_mac,src)->[2]output; // to eth2
};
VNF_OUT[0] -> teth0;
VNF_OUT[1] -> teth1;
VNF_OUT[2] -> teth2;
//-------------------------------------------------------------------//
//      VNF CODE STARTS HERE 
//-------------------------------------------------------------------//
// turns off unused interfaces. 
Idle -> [1]VNF_IN;
VNF_IN[1] -> Discard();
Idle -> [1]VNF_OUT;
// initialization 
Idle() -> Initglobal() -> Discard();
Idle() -> TableTimer();
Idle() -> StateTimer();
Idle() -> DebugTimer();
//---- ethernet layer. 
c0::Classifier(
    0/$eth0_mask 12/8100?000,
    0/$eth0_mask,
    12/8100?000,
    -
);
c2::Classifier(
    0/$eth2_mask 12/0800 23/fe,
    0/$eth2_mask 12/0800 23/fd,
    -
);
//---- IP layer. 
CIPH0::CheckIPHeader(18);
CIPH1::CheckIPHeader(14);
CIPH2::CheckIPHeader(18);
CIPH3::CheckIPHeader(14);
CIPH4::CheckIPHeader(14);
//---- enqueue. 
merged_q::MergedQueue(65535);
pump_q::Pump();
c_pump::Classifier(
    0/$eth0_mask,
    -
);
//---- firewall function. 
tag_detector::TagDetector();
firewall_match::firewallmatch();
firewall_manager::fwmanager();
//---- traffic out, ethernet layer. 
traffic_out :: {
    input[0] -> c::Classifier(6/$server_mask, 6/$client_mask, -);
    c[0] -> StoreEtherAddress($client_mac,dst) -> [0]output;
    c[1] -> StoreEtherAddress($server_mac,dst) -> [0]output;
    c[2] -> Discard();
}; 

//---------------- connection ----------------------------
VNF_IN[0] -> Print() -> c0;
VNF_IN[2] -> c2;
//---- ethernet layer, IP layer, enqueue. 
c0[0] -> CIPH0 -> [0]merged_q;
c0[1] -> CIPH1 -> [1]merged_q;
c0[2] -> CIPH2 -> [2]merged_q;
merged_q[0] -> [0]pump_q;
pump_q[0] -> [0]c_pump;
c0[3] -> Discard();
c2[0] -> CIPH3 -> [1]pump_q;
c2[1] -> CIPH4 -> [1]firewall_manager;
c2[2] -> Discard();
//---- firewall function. 
c_pump[0] -> [0]firewall_match;
c_pump[1] -> [0]tag_detector;
tag_detector[0] -> [1]firewall_match;
firewall_match[0] -> SimpleQueue() -> Unqueue() -> traffic_out -> SimpleQueue() -> [0]VNF_OUT;
firewall_match[1] -> [0]firewall_manager;
firewall_match[2] -> Discard();
firewall_manager[0] -> [1]tag_detector;
firewall_manager[1] -> [2]pump_q;
firewall_manager[2] -> SimpleQueue() -> [2]VNF_OUT;
firewall_manager[3] -> Discard();

