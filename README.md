# vNIDS Project

This is the project for the paper: vNIDS: Towards Elastic Security with Safe and Efficient Virtualization of Network Intrusion Detection System.

This project based on the Click System.

> Click is a modular router toolkit. To use it you'll need to know how to compile and install the software, how to write router configurations, and how to write new elements. This is the Click system office repo link: [Click System](https://github.com/kohler/click)

**Hint**: Please use Ubuntu 16.04 or Ubuntu 14.04 because we have tested this project in these two Ubuntu versions.

## Installing of dependencies

```bash
sudo apt-get install libpcre3 libpcre3-dev
```

## Installing

```bash
./configure
make -j $(getconf _NPROCESSORS_ONLN)
```

## Testing

```bash
./bin/click vids.click
```


## Environment Configuration
We have tested our project with openvswitch and xen virutal machine. Of course, there are some other virtual machines or container can be used to build the enviroment.
Basically, establishing the environment need following steps:.

### Configure the network and the flow rules
To configure the network, a bridge network is needed. You can create a network bridge with openvswitch with only serveral commands.
```bash
ovs-vsctl add-br xenbr0
ovs-vsctl add-port xenbr0 eth0
ifconfig xenbr0 130.127.133.122 netmask 255.255.252.0 broadcast 0.0.0.0 up
ifconfig eth0 0
dhclient xenbr0
```
Then your bridge networking is good to go next. However, to isolate the packets' flow, may be you need to create ip private namespace also.

To customize the flow rules, we have tried the arbitrary ip addresses match of openvswitch. For example, for rules: 0.0.0.1/0.0.0.3, it can only match the add number for the last number in the ip address.
One thing to notices is that your flow rules must guarantee the packets in a flow would dive into a same instance. That's mean to maintain the per-flow states.

### Build the xen vm
To install Xen, there are a lot of materials online. So, just google it.
To enable the openvswitch bridge, you need to add following to your vif configuration. Then, we have the environments.
```bash
['bridge=xenbr0,script=vif-openvswitch']
```

### Install the vNIDS to the VM
This part could be completed with automatic way, Because when VM booted, it can execute scripts automatically. The only thing you need to do is to write the simple shell scripts.

---

## Bugs, Questions, etc

We welcome bug reports, questions, comments, code, whatever you'd like to give us. GitHub issues are the best way to stay in touch.
