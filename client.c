#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h> 
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "phyconnect.h"

// how often to send request (in seconds)
#define SEND_REQUEST_EVERY (2)

// how big is an ssl cert allowed to be (in bytes)
#define MAX_CERT_SIZE (65536)

#define STATE_DISCONNECTED (0)
#define STATE_CONNECTED (1)
#define STATE_DONE (2)

// structs below

struct request {
  uint32_t type;
};

struct response {
  uint32_t type;
  uint32_t lease_ip;
  uint32_t lease_netmask;
  uint32_t cert_size;
};

// global variables below

int src_port = 4243;
int dest_port = 4242;
int received = 0; // how much of current message has been received
char recvbuf[sizeof(struct response) + MAX_CERT_SIZE + 1];
int state = STATE_DISCONNECTED; // track state

// functions declarations below

int broadcast_packet(int sock, void* buffer, size_t len) {
  struct sockaddr_in broadcast_addr;
  int attempts = 3;

  memset(&broadcast_addr, 0, sizeof(broadcast_addr));
  broadcast_addr.sin_family = AF_INET;
  broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
  broadcast_addr.sin_port = htons(dest_port);

  while(sendto(sock, buffer, len, 0, (struct sockaddr *) &broadcast_addr, sizeof(broadcast_addr)) != len) {
    // failed to send entire packet
    if(--attempts) {
      fprintf(stderr, "broadcast failed after several attempts\n");
      usleep(200000);
    } else {
      return -1;
    }
  }
  return 0;
}

int send_request(int sock) {
  struct request req;

  req.type = 42;
  
  return broadcast_packet(sock, (void*) &req, sizeof(req));
}


int receive_complete(struct response* resp, char* cert) {
  struct in_addr tmp_addr;
  
  printf("Response received:\n");
  printf("  type: %d\n", resp->type);
  tmp_addr.s_addr = (unsigned long) resp->lease_ip;
  printf("  lease_ip: %s\n", inet_ntoa(tmp_addr));
  tmp_addr.s_addr = (unsigned long) resp->lease_netmask;
  printf("  lease_subnet: %s\n", inet_ntoa(tmp_addr));
  printf("  cert size: %d\n", resp->cert_size);
  
  if(cert) {
    printf("  cert: %s\n", cert);
  } else {
    printf("  cert: No certificate sent\n");
  }

  // TODO send ACK

  state = STATE_DONE;

  return 0;
}

int handle_incoming(int sock, struct sockaddr_in* addr) {
  struct response* resp;
  ssize_t ret;
  socklen_t addrlen = sizeof(addr);
  char* cert;

  ret = recvfrom(sock, recvbuf + received, sizeof(struct response) + MAX_CERT_SIZE - received, 0, (struct sockaddr*) addr, &addrlen);
  if(ret < 0) {
    if((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      printf("would block\n");
      return 0;
    }
    perror("error receiving packet 1");
    return -1;
  }  
  received += ret;

  // We didn't receive enough data to process, so wait for more
  if(received < sizeof(struct response)) {
    return 0;
  }

  resp = (struct response*) recvbuf;

  if(resp->type != 42) {
    fprintf(stderr, "unknown message type\n");
    return -1;
  }

  if(resp->cert_size == 0) {
    received = 0;
    return receive_complete(resp, NULL);
  }

  if(resp->cert_size > MAX_CERT_SIZE) {
    fprintf(stderr, "server trying to send certificate that's too big\n");
    received = 0;
    return -1;
  }
  
  // There is still more to receive
  if(received < (sizeof(struct response) + resp->cert_size)) {
    return 0;
  }

  received = 0;
  cert = (char*) recvbuf + sizeof(struct response);
  cert[resp->cert_size] = '\0';
  return receive_complete(resp, cert);

  return 0;
}

void physical_ethernet_state_change(char* ifname, int connected) {

  if(connected && (state == STATE_DISCONNECTED)) {
    printf("  %s state: up\n", ifname);
    state = STATE_CONNECTED;
  } else {
    printf("  %s state: down\n", ifname);
    state = STATE_DISCONNECTED;
  }

}

int open_socket(char* ifname, struct sockaddr_in* bind_addr) {
  int sock;
  int sockmode;
  int broadcast_perm;

  if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("creating socket failed");
    return -1;
  }

  if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, 2) < 0) {
    perror("binding to device failed");
    return -1;
  }

  sockmode = fcntl(sock, F_GETFL, 0);
  if(sockmode < 0) {
    perror("error getting socket mode");
    return -1;
  }
  
  if(fcntl(sock, F_SETFL, sockmode | O_NONBLOCK) < 0) {
    perror("failed to set non-blocking mode for socket");
    return -1;
  }

  broadcast_perm = 1;
  if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcast_perm, sizeof(broadcast_perm)) < 0) {
    perror("setting broadcast permission on socket failed");
    return -1;
  }

  if(bind(sock, (struct sockaddr*) bind_addr, sizeof(struct sockaddr_in)) < 0) {
    perror("failed to bind udp socket");
    return -1;
  }

  return sock;
}

int main() {

  fd_set fdset;
  int sock;
  int nlsock;
  int num_ready;
  int max_fd;
  struct sockaddr_in bind_addr;
  struct timeval timeout;
  time_t last_request = 0;
  
  nlsock = netlink_open_socket();
  if(nlsock < 0) {
    fprintf(stderr, "could not open netlink socket\n");
    exit(1);
  }

  if(netlink_send_request(nlsock) < 0) {
    perror("failed to send netlink request");
    exit(1);
  }

  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
  bind_addr.sin_port = htons(src_port);

  sock = open_socket("lo", &bind_addr);
  if(sock < 0) {
    fprintf(stderr, "could not open socket\n");
    exit(1);
  }

  for(;;) {
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    if(nlsock) {
      FD_SET(nlsock, &fdset);
    }
    if(nlsock > sock) {
      max_fd = nlsock;
    } else {
      max_fd = sock;
    }

    timeout.tv_sec = SEND_REQUEST_EVERY;
    timeout.tv_usec = 0;

    if((num_ready = select(max_fd + 1, &fdset, NULL, NULL, &timeout)) < 0) {
      if(errno == EINTR) {
        continue;
      }
      perror("error during select");
    }

    if(FD_ISSET(sock, &fdset)) {
      handle_incoming(sock, &bind_addr);
    }

    if(FD_ISSET(nlsock, &fdset)) {
      netlink_handle_incoming(nlsock, physical_ethernet_state_change);
    }

    if((state == STATE_CONNECTED) && (time(NULL) - last_request >= SEND_REQUEST_EVERY)) {
      printf("Sending request\n");
      send_request(sock);
      last_request = time(NULL);
    }
  }

  
  return 0;
}
