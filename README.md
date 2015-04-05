
THIS IS A WORK IN PROGRESS.

notdhcpserver is not a dhcp server. notdhcpclient is the client for notdhcpserver. 

notdhcpserver and notdhcpclient are how sudo mesh extender nodes get an ip from a sudo mesh home node and how they establish a trust relationship upon physical connection.

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

* Include a checksum in server response
* Make server listen for ACK from client
* Make server stop listening on an interface when ACK has been received and then only start listening again after a physical ethernet disconnect and connect.
* Deal with network byte order vs host byte order

## Limitations

* The file of the certificate file must be less than 64 kB. This can be changed by changing MAX_CERT_SIZE in main.c and recompiling.
# License and copyright

# client 

## Usage

When an extender node receives a response, it will run the script specified with -s on the command line, passing the interface name, IP, netmask and path to SSL cert as the 1st, 2nd, 3rd and 4th command-line arguments to the script. 

## TODO

* Command line args
* Make it write received ssl cert to file
* Support for hook script
* Add timeout so it abandons an incoming message if no data is received for a long time 

# License and copyright

This software is licensed under the GNU General Public License v3.

Copyright 2015 Marc Juul.