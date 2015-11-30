
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "phyconnect.h"

// No idea if this is a good size
#define MAX_MSG_SIZE (8192)

/*
  Simple couple of functions to listen to a netlink socket
  and run a callback whenever a network interface is physically
  connected or disconnected, e.g. ethernet link established.
*/

int netlink_open_socket() {
  struct sockaddr_nl nladdr;
  int nlsock;
  int sockmode;

  if((nlsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
    perror("creating netlink socket failed");
    return -1;
  }

  bzero(&nladdr, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_pad = 0;
  nladdr.nl_pid = getpid();
  nladdr.nl_groups = RTMGRP_LINK; // network interface create/delete/up/down
  if(bind(nlsock, (struct sockaddr*) &nladdr, sizeof(nladdr)) < 0) {
    perror("could not bind netlink socket");
    return -1;
  }

  sockmode = fcntl(nlsock, F_GETFL, 0);
  if(sockmode < 0) {
    perror("error getting socket mode");
    return -1;
  }
  
  if(fcntl(nlsock, F_SETFL, sockmode | O_NONBLOCK) < 0) {
    perror("failed to set non-blocking mode for socket");
    return -1;
  }

  return nlsock;
}


// The callback will receive two arguments:
//   1. The interface name
//   2. 0 if the interface connected and 1 if it disconnected
int netlink_handle_incoming(int nlsock, void (*callback)(char*, int)) {
  struct nlmsghdr* nlheader;
  struct nlmsghdr* cur;
  struct ifinfomsg* ifmsg;
  struct rtattr* rta;
  int rta_len;
  uint8_t* operstate;
  char* ifname = NULL;
  int len;
  ssize_t received = 0;
  int got_operstate = 0;
  
  nlheader = (struct nlmsghdr*) malloc(MAX_MSG_SIZE);

  while(received < sizeof(struct nlmsghdr)) {
    len = recv(nlsock, nlheader, MAX_MSG_SIZE, 0);
    if(len == 0) {
      break;
    }
    if(len < 0) {
      perror("error receiving netlink data");
      free(nlheader);
      return -1;
    }
    received += len;
  }

  // iterate over netlink messages
  for(cur = nlheader; (NLMSG_OK(cur, received)) && (cur->nlmsg_type != NLMSG_DONE); cur = NLMSG_NEXT(cur, received)) {
    got_operstate = 0;
    ifname = 0;

    if(cur->nlmsg_type != RTM_NEWLINK) {
      continue;
    }
    ifmsg = (struct ifinfomsg*) NLMSG_DATA(cur);
    
    rta_len = cur->nlmsg_len - NLMSG_LENGTH(sizeof(*ifmsg));
    // iterate over message attributes
    for(rta = IFLA_RTA(ifmsg); RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
      if(rta->rta_type == IFLA_IFNAME) {
        ifname = (char*) RTA_DATA(rta);
      }
      // get the "operstate" 
      // see http://lxr.cpsc.ucalgary.ca/lxr/#linux+v2.6.33/Documentation/networking/operstates.txt
      if(rta->rta_type == IFLA_OPERSTATE) {
        operstate = (uint8_t*) RTA_DATA(rta);
        got_operstate = 1;
      }
    }

    if(ifname && got_operstate && callback) {
      printf("operstate for %s: %u\n", ifname, *operstate);
      syslog(LOG_DEBUG, "operstate for %s: %u\n", ifname, *operstate);
      // From link above: Interface is in unknown state, neither driver nor userspace has set
      // operational state. Interface must be considered for user data as
      // setting operational state has not been implemented in every driver.
      if(*operstate == 6 || *operstate == 0) {
        callback(ifname, 1);
      } else {
        callback(ifname, 0);
      }
    }
  }

  free(nlheader);
  return 0;
}



int netlink_send_request(int nlsock) {
  
  struct sockaddr_nl addr;
  struct msghdr hdr;
  struct nl_req req;
  struct iovec io;
  ssize_t ret;

  memset(&addr, 0, sizeof(addr));
  memset(&hdr, 0, sizeof(hdr));
  memset(&req, 0, sizeof(req));
  
  addr.nl_family = AF_NETLINK;
  addr.nl_pad = 0; // always zero
  addr.nl_pid = 0; // zero means send to kernel
  addr.nl_groups = 0; // no groups

  
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
  req.hdr.nlmsg_type = RTM_GETLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = 1;
  req.hdr.nlmsg_pid = getpid();
  req.gen.rtgen_family = AF_PACKET;

  io.iov_base = (void*) &req;
  io.iov_len = req.hdr.nlmsg_len;
  hdr.msg_iov = &io;
  hdr.msg_iovlen = 1;
  hdr.msg_name = &addr;
  hdr.msg_namelen = sizeof(addr);

  // send the RTNETLINK message to kernel
  ret = sendmsg(nlsock, (struct msghdr*) &hdr, 0);
  if(ret < 0) {
    return ret;
  }

  return 0;
}
