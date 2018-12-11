
## Source code
The click source code is forked from [Click modular router](https://github.com/kohler/click)

These files are developed by us:

| codes | Description |
|-------| ----------- |
| elements/standard/firewallmatch.cc elements/standard/firewalltable.cc elements/standard/fwmanager.cc elements/standard/initglobal.cc elements/standard/firewallmatch.hh elements/standard/firewalltable.hh elements/standard/fwmanager.hh elements/standard/initglobal.hh | elements for firewall |
| nfv | scripts for firewall |
| elements/vids | elements for virtual network intrusion detection system, you should know how to use these elements. |
|include/click/logger.h include/clicknet/dns.h include/clicknet/geneve.h include/clicknet/http.h include/utils.hh lib/dns.cc lib/event.cc lib/http.cc lib/packet_tags.cc lib/utils.cc | utils files we developed |
| exps/userlevel/vids/ | Scripts |

## Build userlevel click with RamCloud client
After you build RamCloud and install it.
Run
`ldconfig -p | grep ramcloud`

you can find the dynamic link library `libramcloud.so`.

Then configure the click with ramcloud

`./configure LIBS="-lramcloud -L/usr/local/lib/ramcloud" --disable-linuxmodule`

Build it

`make -j $(getconf _NPROCESSORS_ONLN) userlevel`

## Documentation
`cd doc; make doxygen O=html; cd ..`

This will generate html documentation in `html` folder. You can open the index.html in browser.

## vids scripts
Before setting the nic, you should have a bridge named ovs-lan in your ovs.
Run `ovs-vsctl show` to figure out.

If ovs-lan bridge is showing in the previous results, setup nic

`exps/userlevel/vids/bin/set_nics.sh 2`

This script will add 2 pairs of network interfaces, and change their mac addresses.


### Run lw
`ip netns exec click_ns_1 bin/click exps/userlevel/vids/conf/lw.click`

### Run hw
`ip netns exec click_ns_2 bin/click exps/userlevel/vids/conf/hw.click`

 

## FAQ





