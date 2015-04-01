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

struct request {
  uint32_t type;
};

struct response {
  uint32_t type;
  uint32_t lease_ip;
  uint32_t lease_netmask;
  char password[PASSWORD_LENGTH];
};

int src_port = 4242;
int dest_port = 4243;

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

int handle_incoming(int sock, struct sockaddr_in* addr) {
  struct request req;
  ssize_t ret;
  ssize_t received = 0;
  socklen_t addrlen = sizeof(addr);
  
  while(received < sizeof(req)) {
    ret = recvfrom(sock, &req, sizeof(req), 0, (struct sockaddr*) addr, &addrlen);
    if(ret < 0) {
      perror("error receiving packet");
      break;
    }
    received += ret;
  }
  
  // TODO this is just an example response
  if(req.type == 42) {
    return send_response(sock, "100.64.2.2", "255.192.0.0", "0123456701234567");
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

int main(int argc, char** argv) {

  fd_set fdset;
  int sock;
  struct sockaddr_in bind_addr;
  int broadcast_perm;
  int packetlen;
  int num_ready;
  int sockmode;
  int c;
  int verbose = 0;
  extern int optind;

  if(argc <= 0) {
    usagefail(NULL);
    return 1;
  }

  while((c = getopt(argc, argv, "dh")) != -1) {
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

  if(argc < optind+2) {
    usagefail(argv[0]);
    return;
  }

  
  if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("creating socket failed");
    return 1;
  }

  if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", 2) < 0) {
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

  printf("Listening for requests\n");

  for(;;) {
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    if((num_ready = select(sock + 1, &fdset, NULL, NULL, NULL)) < 0) {
      if(errno == EINTR) {
        printf("huh?\n");
        continue;
      }
      perror("error during select");
    }
    printf("select returned\n");

    if(FD_ISSET(sock, &fdset)) {
      printf("Request received!\n");
      if(handle_incoming(sock, &bind_addr) < 0) {
        perror("error handling incoming packet");
      } else {
        printf("Response sent!\n");
      }
    }
  }

  
  return 0;
}
