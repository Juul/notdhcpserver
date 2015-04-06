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

#include "protocol.h"
#include "phyconnect.h"

// how often to send request (in seconds)
#define SEND_REQUEST_EVERY (2)

// how big is an ssl cert allowed to be (in bytes)
#define MAX_CERT_SIZE (65536)

#define STATE_DISCONNECTED (0)
#define STATE_CONNECTED (1)
#define STATE_DONE (2)

// global variables below

int src_port = 4243;
int dest_port = 4242;
int received = 0; // how much of current message has been received
char recvbuf[sizeof(struct response) + MAX_CERT_SIZE + 1];
int state = STATE_DISCONNECTED; // track state
int verbose = 0;
char* hook_script_path = NULL;
char* listen_ifname = NULL; // interface name to listen on
char* ssl_cert_path = NULL; // where to write ssl cert
char* ssl_key_path = NULL; // where to write ssl key

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


void run_hook_script(char* ip, char* netmask, char* password, char* cert_path, char* key_path) {
  if(!hook_script_path) {
    return;
  }

  if(execl(hook_script_path, listen_ifname, ip, netmask, password, cert_path, key_path, NULL) < 0) {
    perror("error running hook script");
  }
}

int receive_complete(struct response* resp, char* cert, char* key) {
  struct in_addr tmp_addr;
  FILE* out;
  size_t written;
  int wrote_cert = 0;
  int wrote_key = 0;
  
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

  // write ssl cert
  if(ssl_cert_path && cert) {
    out = fopen(ssl_cert_path, "w+");
    if(!out) {
      perror("failed to write SSL cert");
    }
    written = fwrite(cert, 1, resp->cert_size, out);
    if(written != resp->cert_size) {
      perror("failed to write SSL cert");
    } else {
      wrote_cert = 1;
    }
    fclose(out);
  }

  // write ssl key
  if(ssl_key_path && key) {
    out = fopen(ssl_key_path, "w+");
    if(!out) {
      perror("failed to write SSL key");
    }
    written = fwrite(key, 1, resp->key_size, out);
    if(written != resp->key_size) {
      perror("failed to write SSL key");
    } else {
      wrote_cert = 1;
    }
    fclose(out);
  }

  if(wrote_cert && wrote_key) {
    run_hook_script(inet_ntoa(tmp_addr), inet_ntoa(tmp_addr), resp->password, ssl_cert_path, ssl_key_path);
  } else {
    run_hook_script(inet_ntoa(tmp_addr), inet_ntoa(tmp_addr), resp->password, NULL, NULL);
  }

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
    return receive_complete(resp, NULL, NULL);
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
  return receive_complete(resp, cert, NULL); // TODO also receive key 

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

// call with e.g. usage(argv[0], stdin) or usage(argv[0], stderr)
void usage(char* command_name, FILE* out) {
  char default_command_name[] = "notdhcpclient";
  if(!command_name) {
    command_name = (char*) &default_command_name;
  }
  fprintf(out, "Usage: %s [-v] interface\n", command_name);
  fprintf(out, "\n");
  fprintf(out, "  -s hook_script: Hook script to run upon receiving \"lease\"\n");
  fprintf(out, "  -c ssl_cert: Where to write SSL cert\n");
  fprintf(out, "  -k ssl_key: Where to write SSL key\n");
  fprintf(out, "  -v: Enable verbose mode\n");
  fprintf(out, "  -h: This help text\n");
  fprintf(out, "\n");
  fprintf(out, "Example usage:\n");
  fprintf(out, "\n");
  fprintf(out, "  %s eth0\n", command_name);
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
  int nlsock;
  int num_ready;
  int max_fd;
  struct sockaddr_in bind_addr;
  struct timeval timeout;
  time_t last_request = 0;
  int c;
  
  if(argc <= 0) {
    usagefail(NULL);
    exit(1);
  }

  while((c = getopt(argc, argv, "s:c:k:vh")) != -1) {
    switch (c) {
    case 's':
      hook_script_path = optarg;
      break;
    case 'c':
      ssl_cert_path = optarg;
      break;
    case 'k':
      ssl_key_path = optarg;
      break;
    case 'v': 
      printf("Verbose mode enabled\n");
      verbose = 1; 
      break; 
    case 'h':
      usage(argv[0], stdout);
      exit(0);
    }
  }

  // need at least one non-option argument
  if(argc < optind + 1) {
    usagefail(argv[0]);
    exit(1);
  }

  listen_ifname = argv[optind];

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

  sock = open_socket(listen_ifname, &bind_addr);
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
