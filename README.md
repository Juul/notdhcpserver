
THIS IS A WORK IN PROGRESS. NONE OF THIS WORKS YET.

notdhcpserver is not a dhcp server.

notdhcpserver and notdhcpclient are how sudo mesh radio nodes get an ip from an indoor sudo mesh nodes and how they establish a trust relationship upon physical connection.

The protocol is very simple:

# Radio node ethernet is plugged into a radio node port on an indoor node
# The radio node sends out a UDP broadcast packet on port 4242 to IP 255.255.255.255
# The indoor node sees the UDP packet and responds with both an IP for the radio node and a password for the node to use for web admin. This is also a UDP broadcast packet but on destination port 4243.
# The radio node acknowledges reception of IP and password by sending a UDP packet to the IP of the indoor node from its new IP and on port 4242.

