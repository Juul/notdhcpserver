#include <string.h>
#include <stdarg.h>
#include <ctype.h>
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

#define PASSWORD_LENGTH (16)

// structs below

struct interface {
  char* ifname;
  char* ip;
  char* netmask;
  int sock;
  struct sockaddr_in* addr;
  struct interface* next;
};

struct request {
  uint32_t type;
};

struct response {
  uint32_t type;
  uint32_t lease_ip;
  uint32_t lease_netmask;
  char password[PASSWORD_LENGTH];
};

// global variables below

int verbose = 0;
int src_port = 4242;
int dest_port = 4243;
struct interface* interfaces = NULL;

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

int send_response(int sock, const char* lease_ip, const char* lease_netmask, const char* password) {
  struct response resp;

  resp.type = 42;
  resp.lease_ip = inet_addr(lease_ip);
  resp.lease_netmask = inet_addr(lease_netmask);
  memcpy(resp.password, password, PASSWORD_LENGTH);
  
  return broadcast_packet(sock, (void*) &resp, sizeof(resp));
}

int handle_incoming(struct interface* iface) {
  struct request req;
  ssize_t ret;
  ssize_t received = 0;
  socklen_t addrlen = sizeof(iface->addr);
  
  while(received < sizeof(req)) {
    ret = recvfrom(iface->sock, &req, sizeof(req), 0, (struct sockaddr*) &(iface->addr), &addrlen);
    if(ret < 0) {
      perror("error receiving packet");
      break;
    }
    received += ret;
  }
  
  // TODO this is just an example response
  if(req.type == 42) {
    return send_response(iface->sock, iface->ip, iface->netmask, "0123456701234567");
  }

  return -1;
}

// call with e.g. usage(argv[0], stdin) or usage(argv[0], stderr)
void usage(char* command_name, FILE* out) {
  char default_command_name[] = "notdhcpserver";
  if(!command_name) {
    command_name = (char*) &default_command_name;
  }
  fprintf(out, "Usage: %s [-v] ifname=ip [ifname2=ip2 ...]\n", command_name);
  fprintf(out, "\n");
  fprintf(out, "  -v: Enable verbose mode\n");
  fprintf(out, "  -h: This help text\n");
  fprintf(out, "\n");
  fprintf(out, "For each interface where you want nodhcpserver to hand out an IP \"lease\"\n");
  fprintf(out, "specify an interface+ip pair. E.g:\n");
  fprintf(out, "\n");
  fprintf(out, "  %s eth0.2=100.64.0.2 eth0.3=100.64.0.3\n", command_name);
  fprintf(out, "\n");
}

void usagefail(char* command_name) {
  fprintf(stderr, "Error: Missing required command-line arguments.\n\n");
  usage(command_name, stderr);
  return;
}

struct interface* new_interface(char* ifname, char* lease_ip, char* lease_netmask) {
  struct interface* iface = (struct interface*) malloc(sizeof(struct interface));

  iface->ifname = (char*) malloc(strlen(ifname)+1);
  iface->ip = (char*) malloc(strlen(lease_ip)+1);
  iface->netmask = (char*) malloc(strlen(lease_netmask)+1);
  iface->addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));

  memcpy(iface->ifname, ifname, strlen(ifname)+1);
  memcpy(iface->ip, lease_ip, strlen(lease_ip)+1);
  memcpy(iface->netmask, lease_netmask, strlen(lease_netmask)+1);

  return iface;
}

/*
struct interface* get_interface_by_sock(int sock) {
  struct interface* iface;
  iface = interfaces;
  do {
    if(iface->sock == sock) {
      return iface;
    }
  } while(iface = iface->next);

  return NULL;
}
*/

// add interface to linked list and return the previous end of the linked list
struct interface* add_interface(struct interface* iface) {
  struct interface* cur = interfaces;

  if(!interfaces) {
    interfaces = iface;
  } else {
    while(cur->next) {
      cur = cur->next;
    }
    cur->next = iface;
  }
  return cur;
}


int monitor_interface(char* ifname, char* lease_ip, char* lease_netmask) {

  struct sockaddr_in bind_addr;
  int broadcast_perm;
  int packetlen;
  int sockmode;
  int sock;

  struct interface* iface = new_interface(ifname, lease_ip, lease_netmask);

  if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("creating socket failed");
    return 1;
  }

  if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0) {
    perror("binding to device failed");
    return 1;
  }

  sockmode = fcntl(sock, F_GETFL, 0);
  if(sockmode < 0) {
    perror("error getting socket mode");
    return 1;
  }
  
  if(fcntl(sock, F_SETFL, sockmode | O_NONBLOCK) < 0) {
    perror("failed to set non-blocking mode for socket");
    return 1;
  }

  broadcast_perm = 1;
  if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcast_perm, sizeof(broadcast_perm)) < 0) {
    perror("setting broadcast permission on socket failed");
    return 1;
  }

  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
  bind_addr.sin_port = htons(src_port);

  if(bind(sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr)) < 0) {
    perror("failed to bind udp socket");
    return 1;
  }

  iface->sock = sock;
  *(iface->addr) = bind_addr;
  add_interface(iface);

  return 0;
}


int main(int argc, char** argv) {

  fd_set fdset;
  int max_fd;
  int num_ready;
  extern int optind;
  struct interface* iface;
  int c;

  if(argc <= 0) {
    usagefail(NULL);
    return 1;
  }

  while((c = getopt(argc, argv, "vh")) != -1) {
    switch (c) { 
    case 'v': 
      printf("Verbose mode enabled\n");
      verbose = 1; 
      break; 
    case 'h':
      usage(argv[0], stdout);
      return 0;
    }
  }

  if(argc < optind + 1) {
    usagefail(argv[0]);
    return;
  }

  monitor_interface("lo", "100.64.2.3", "255.255.255.192");

  printf("Listening for requests\n");

  for(;;) {

    // initialize fdset
    FD_ZERO(&fdset);
    max_fd = 0;
    iface = interfaces;
    do {
      FD_SET(iface->sock, &fdset);
      if(iface->sock > max_fd) {
        max_fd = iface->sock;
      }
    } while(iface = iface->next);

    if((num_ready = select(max_fd + 1, &fdset, NULL, NULL, NULL)) < 0) {
      if(errno == EINTR) {
        printf("huh?\n");
        continue;
      }
      perror("error during select");
    }

    iface = interfaces;
    do {
      if(FD_ISSET(iface->sock, &fdset)) {
        if(verbose) {
          printf("Packet received on interface %s\n", iface->ifname);
        }

        if(handle_incoming(iface) < 0) {
          perror("Error handling incoming packet");
        } else {
          printf("Response sent!\n");
        }

      }
    } while(iface = iface->next);
  }  
  
  return 0;
}
