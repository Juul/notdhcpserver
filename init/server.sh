#!/bin/sh


# TODO finish and test

# Location of notdhcpserver binary
SERVER_PATH=/usr/bin/notdhcpserver

# Where to write PID file
PIDFILE=/var/run/notdhcpserver.pid

# Arguments to pass to server
# You can add -v to make it more verbose
SERVER_ARGS=""

# Hook script to execute when an IP has been handed out
HOOK_SCRIPT=/opt/notdhcpserver/hook.sh

# SSL certificate and key to send to clients
SSL_CERT=/etc/notdhcp/client.cert
SSL_KEY=/etc/notdhcp/client.key

# Interfaces with the IP and subnet for each client on that interface
# Note: Only one IP per interface is supported. 
# See the readme file if this is confusing.
IFACES="eth0.1=100.64.2.2/255.255.255.255 eth0.2=100.64.2.3/255.255.255.255"

start-stop-daemon --start --make-pidfile --pidfile $PIDFILE --background --startas /bin/sh -- "exec $SERVER_PATH $SERVER_ARGS -c $SSL_CERT -k $SSL_KEY -s $HOOK_SCRIPT $IFACES &> logger"
