
notdhcpserver is not a dhcp server. notdhcpclient is the client for notdhcpserver. 

notdhcpserver and notdhcpclient are how sudo mesh extender nodes get an ip from a sudo mesh home node and how they establish a trust relationship upon physical connection.

WE DO NOT YET CONSIDER THIS STABLE SOFTWARE.

# Compiling

## Compiling for a non-OpenWRT system

Simply do:

```
make not
```

## Cross-compiling

Before you embark on this, note that we already have an OpenWRT feed for this package here:

```
https://github.com/sudomesh/sudowrt-packages
```

However, the ability to rapidly re-compile is useful during development. 

You can cross-compile using an existing OpenWRT toolchain. This will result in binaries with support for physical link state detection on integrated switch ethernet ports. You need to ensure that you have already compiled OpenWRT and that you have included libnl. 

To cross-compile, first:

```
cp cross_compile_env.sh.example cross_compile_env.sh
```

Then edit cross_compile_env.sh changing all of the paths what makes sense for (compiled) your OpenWRT build and run:

```
. cross_compile_env.sh
```

Now you can cross-compile with:

```
make
```


This will set a bunch of environment variables for the current shell.

# Protocol

The protocol is very simple:

* An extender node's ethernet cable is plugged into on of the dedicated extender-node-ethernet-ports on a home node.
* Every few seconds the extender node sends out a UDP broadcast packet on port 4242 to IP 255.255.255.255
* The home node sees the UDP packet and responds with both an IP/subnet for the extender node and an SSL certificate for the node. This is also a UDP broadcast packet but on destination port 4243.
* The extender node will keep sending requests every few seconds until it receives a response.
* The extender node will then send an acknowledgement and stop sending requests
* When the ack is received by the home node, the home node will stop listening on the interface.
* If the physical connection between home node and extender node is disconnected and reconnected then both home node and extender node will start the process again.

# server

## Usage

When the home node receives an ack it will run the script specified with -s on the command line, passing the interface name, IP and netmask as the 1st, 2nd and 3rd arguments.

## TODO

Immediate:

* CRC for UDP isn't implemented

Future:

* Add SSL-generation and per-client SSL certs.
* IPv6 support

## Limitations

* The server is for handing out one single IP per interface ONLY. This is not a replacement for a real DHCP server. If you're not using the sudo mesh firmware then you probably don't want this.
* The certificate and key file must each be less than 16 kB. This can be changed by changing MAX_CERT_SIZE and MAX_KEY_SIZE in protocol.h and recompiling.
* Hook scripts are run with /bin/sh but this can be changed in common.h

# client 

## Usage

When an extender node receives a response, it will run the hook script specified with -s on the command line, passing the following arguments:

When client gets an IP:

1. The string "up"
2. The receiving interface name
3. The received IP
4. The received netmask
5. The received password
6. Path to the received SSL certificate (optional)
7. Path to the received SSL key (optional)

When physical connection goes away:

1. The string "down"
2. The receiving interface name

# Integrated switches

notdhcpserver and notdhcpclient can detect physical ethernet link state changes both on normal ethernet interface and on ethernet ports on integrated switches (as is common in home routers). If you are using a device with an integrated switch, then your ethernet interfaces will be called e.g. eth0.1, eth0.2 etc. where the ".1" and ".2" denote the VLAN id. 

nothdcp ASSUMES YOU HAVE ONE SWITCH PORT PER INTERFACE: If you have e.g. eth0.1 mapped to e.g. port 1, 2, 3 and 4 then it will listen for port connect and disconnect events only on port 1! 

The switch will have been set up to map incoming traffic on each switch port to a certain VLAN id, and this mapping is understood by notdhcp though there are some pitfalls to be aware of. 

The same VLAN ids can be set on multiple ports, so the mapping is not one to one. All VLAN ids are already set on port 0 since port 0 is an internal port that is hardwired to the CPU. notdhcp ignores port 0 for this reason and simply picks the first non-zero port associated with a VLAN id. This means that notdhcp will not work correctly if e.g. you have eth0.1 which is associated with more than one port (ignoring port 0). notdhcp assumes that you have one port per in

You can use the swconfig utility (included in OpenWRT) to investigate the switch port and VLAN mapping.

## TODO

Immediate:

* CRC for UDP isn't implemented
* Make it keep receiving until there is no more to receive
* Add timeout so it abandons an incoming message if no data is received for a few seconds

Future:

* IPv6 support

# Running as daemon

The server and client currently do not include any functionality for running as a daemon natively. See the sample init scripts in the init/ directory for how to run as a daemon using start-stop-daemon.

# FAQ

* Q: Why did you write this? Why not just use the dnsmasq dhcp server?
* A: The behaviour we want is very specific. nothdcpserver hands out only one IP per interface and does not keep track of lease time. Every time there is a physical disconnect on the interface the state is reset. dnsmasq uses the IP of each interface to decide which dhcp-range to hand out on that interface. This is problematic since we use the same IP on multiple non-bridged interfaces. We still use dnsmasq for normal DHCP. We are also handing out an SSL cert and key along with the IP. Lastly, we don't want to give these IPs out to anything that isn't an extender node and we want to run both notdhcpserver and dnsmasq dhcp server on the same interface at the same time such that the interface can work as an extra LAN port until an extender node is plugged in, at which time it will be switched over to become a dedicated extender node port.

# About swlib

Since swlib has not been broken out as a separate package, I simply copied the files from the OpenWRT swconfig package.

# License and copyright

The following is true for everything except the files in the swlib/ directory:

This software is licensed under the GNU General Public License v3.

Copyright 2015 Marc Juul.