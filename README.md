
THIS IS A WORK IN PROGRESS. NONE OF THIS WORKS YET.

notdhcpserver is not a dhcp server.

notdhcpserver and notdhcpclient are how sudo mesh radio nodes get an ip from an indoor sudo mesh nodes and how they establish a trust relationship upon physical connection.

# Protocol

The protocol is very simple:

* An extender node's ethernet cable is plugged into on of the dedicated extender-node-ethernet-ports on a home node
* The extender node sends out a UDP broadcast packet on port 4242 to IP 255.255.255.255
* The home node sees the UDP packet and responds with both an IP for the extender node and a password for the node to use for web admin. This is also a UDP broadcast packet but on destination port 4243.
* The extender node will keep sending requests every few seconds until it receives a response

# Usage

When an extender node receives a response, it will run the script specified with -s on the command line, passing the IP, netmask and password as the 1st, 2nd and 3rd command-line arguments to the script.

# TODO

* Make server send response three times with small delay between each (UDP is unreliable after all)
* Include a checksum in server response
* Generate randomized password
* Make server listen for ACK from client
* Make server stop listening on an interface when ACK has been received and then only start listening again after a physical ethernet disconnect and connect.
* Deal with network byte order vs host byte order


# Limitations

* The file of the certificate file must be less than 16 kB. This can be changed by changing MAX_CERT_SIZE in main.c and recompiling.
# License and copyright

This software is licensed under the GNU General Public License v3.0

Copyright 2015 Marc Juul.