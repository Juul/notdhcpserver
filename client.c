#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
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

#include "crc32.h"
#include "common.h"
#include "protocol.h"
#include "phyconnect.h"

// how often to send request (in seconds)
#define SEND_REQUEST_EVERY (2)

#define STATE_DISCONNECTED (0)
#define STATE_CONNECTED (1)
#define STATE_DONE (2)

// global variables below

struct sockaddr_in bind_addr;
struct sockaddr_ll bind_addr_raw;
int sock; // for receiving and sending ack
int sock_raw; // for sending initial request
int received = 0; // how much of current message has been received
char recvbuf[MAX_RESPONSE_SIZE]; // the extra two bytes are to null-terminate 
int state = STATE_DISCONNECTED; // track state
int verbose = 0;
char* hook_script_path = NULL;
char* listen_ifname = NULL; // interface name to listen on
char* ssl_cert_path = NULL; // where to write ssl cert
char* ssl_key_path = NULL; // where to write ssl key

// functions declarations below

uint32_t calc_crc(struct response* resp, size_t len) {
  return crc32((char*) (resp) + sizeof(resp->crc), len - sizeof(resp->crc));
}

int broadcast_packet_raw(int sock, void* buffer, size_t len, struct sockaddr_ll* bind_addr) {
  int attempts = 3;
  
  while(raw_udp_broadcast(sock, buffer, len, CLIENT_PORT, SERVER_PORT, bind_addr) != len) {
    // failed to send entire packet
    if(attempts--) {
      usleep(200000);
    } else {
      syslog(LOG_ERR, "broadcast failed after several attempts\n");
      return -1;
    }
  }
  return 0;
}

int broadcast_packet(int sock, void* buffer, size_t len) {
  struct sockaddr_in broadcast_addr;
  int attempts = 3;

  memset(&broadcast_addr, 0, sizeof(broadcast_addr));
  broadcast_addr.sin_family = AF_INET;
  broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
  broadcast_addr.sin_port = SERVER_PORT;

  while(sendto(sock, buffer, len, 0, (struct sockaddr *) &broadcast_addr, sizeof(broadcast_addr)) != len) {
    // failed to send entire packet
    if(--attempts) {
      syslog(LOG_ERR, "broadcast failed after several attempts\n");
      usleep(200000);
    } else {
      return -1;
    }
  }
  return 0;
}


int send_request(int sock, struct sockaddr_ll* bind_addr) {
  struct request req;

  req.type = htonl(REQUEST_TYPE_GETLEASE);
  
  return broadcast_packet_raw(sock_raw, (void*) &req, sizeof(req), bind_addr);
}


  /*
void run_hook_script(const char* up_or_down, char* ip, char* netmask, char* password, char* cert_path, char* key_path) {
  char* cmd;
  if(!hook_script_path) {
    return;
  }

  


  if(execl(SHELL_COMMAND, hook_script_path, listen_ifname, up_or_down, ip, netmask, password, cert_path, key_path, NULL) < 0) {
    syslog(LOG_DEBUG, "error running hook script");
  }
}
  */

int send_triple_ack(int sock) {
  struct request req;
  int times = 3;

  req.type = htonl(REQUEST_TYPE_ACK);

  while(times--) {
    if(broadcast_packet(sock, (void*) &req, sizeof(req)) < 0) {
      return -1;
    }
    usleep(100000);
  }
  return 0;
}

int receive_complete(int sock, struct response* resp, char* cert, char* key) {
  struct in_addr ip_addr;
  struct in_addr subnet_addr;
  FILE* out;
  size_t written;
  int wrote_cert = 0;
  int wrote_key = 0;

  ip_addr.s_addr = (unsigned long) resp->lease_ip;
  subnet_addr.s_addr = (unsigned long) resp->lease_netmask;

  if(verbose) {
    syslog(LOG_DEBUG, "Response received:\n");
    syslog(LOG_DEBUG, "  type: %d\n", resp->type);
    syslog(LOG_DEBUG, "  lease_ip: %s\n", inet_ntoa(ip_addr));
    syslog(LOG_DEBUG, "  lease_subnet: %s\n", inet_ntoa(subnet_addr));
    syslog(LOG_DEBUG, "  cert size: %d\n", resp->cert_size);
  }
  
  if(send_triple_ack(sock) < 0) {
    return -1;
  }

  state = STATE_DONE;

  // write ssl cert
  if(ssl_cert_path && cert) {
    out = fopen(ssl_cert_path, "w+");
    if(!out) {
      syslog(LOG_DEBUG, "failed to write SSL cert");
    }
    written = fwrite(cert, 1, resp->cert_size - 1, out);
    if(written != (resp->cert_size - 1)) {
      syslog(LOG_ERR, "failed to write SSL cert: incomplete write\n");
    } else {
      wrote_cert = 1;
    }
    fclose(out);
  }

  // write ssl key
  if(ssl_key_path && key) {
    out = fopen(ssl_key_path, "w+");
    if(!out) {
      syslog(LOG_DEBUG, "failed to write SSL key");
    }
    written = fwrite(key, 1, resp->key_size - 1, out);
    if(written != (resp->key_size - 1)) {
      syslog(LOG_ERR, "failed to write SSL key: incomplete write\n");
    } else {
      wrote_cert = 1;
    }
    fclose(out);
  }

  if(wrote_cert && wrote_key) {
    run_hook_script(hook_script_path, "up", inet_ntoa(ip_addr), inet_ntoa(subnet_addr), resp->password, ssl_cert_path, ssl_key_path, NULL);
  } else {
    run_hook_script(hook_script_path, "down", inet_ntoa(ip_addr), inet_ntoa(subnet_addr), resp->password, NULL);
  }

  return 0;
}

int handle_incoming(int sock) {
  struct response* resp;
  ssize_t ret;
  socklen_t addrlen = sizeof(bind_addr);
  char* cert;
  char* key;
  int total_size;

  ret = recvfrom(sock, recvbuf + received, MAX_RESPONSE_SIZE - received, 0, (struct sockaddr*) &bind_addr, &addrlen);
  if(ret < 0) {
    if((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      return 0;
    }
    syslog(LOG_DEBUG, "error receiving packet 1");
    return 1;
  }  
  received += ret;

  // We didn't receive enough data to process, so wait for more
  if(received < sizeof(struct response)) {
    return 1;
  }

  resp = (struct response*) recvbuf;

  total_size = sizeof(struct response) + ntohl(resp->cert_size) + ntohl(resp->key_size);

  resp->type = ntohl(resp->type);
  resp->lease_ip = ntohl(resp->lease_ip);
  resp->lease_netmask = ntohl(resp->lease_netmask);
  resp->cert_size = ntohl(resp->cert_size);
  resp->key_size = ntohl(resp->key_size);

  if(resp->type != RESPONSE_TYPE) {
    if(verbose) {
      syslog(LOG_DEBUG, "Unknown data received\n");
    }
    return 1;
  }

  if((resp->cert_size == 0) && (resp->key_size == 0)) {
    received = 0;
    receive_complete(sock, resp, NULL, NULL);
    return 1;
  }

  if(resp->cert_size > MAX_CERT_SIZE) {
    syslog(LOG_ERR, "server trying to send SSL certificate that's too big\n");
    received = 0;
    return 1;
  }

  if(resp->key_size > MAX_KEY_SIZE) {
    syslog(LOG_ERR, "server trying to send SSL key that's too big\n");
    received = 0;
    return 1;
  }
  
  // There is still more to receive
  if(received < (sizeof(struct response) + resp->cert_size + resp->key_size)) {
    return 1;
  }

  received = 0; // reset received counter, ready for next message

  cert = (char*) recvbuf + sizeof(struct response);
  cert[resp->cert_size - 1] = '\0';

  key = (char*) recvbuf + sizeof(struct response) + resp->cert_size;
  key[resp->key_size - 1] = '\0';

  receive_complete(sock, resp, cert, key);
  return 1;
}

void physical_ethernet_state_change(char* ifname, int connected) {

  // ignore events for other interfaces 
  if(strcmp(ifname, listen_ifname) != 0) {
    return;
  }

  if(connected && (state == STATE_DISCONNECTED)) {
    syslog(LOG_DEBUG, "%s: Physical connection detected\n", ifname);

    sock_raw = open_raw_socket(ifname, &bind_addr_raw);
    if(sock_raw < 0) {
      syslog(LOG_ERR, "Fatal error: Could not re-open socket\n");
      exit(1);
    }

    sock = open_socket(ifname, &bind_addr);
    if(sock < 0) {
      syslog(LOG_ERR, "Fatal error: Could not re-open socket\n");
      exit(1);
    }

    state = STATE_CONNECTED;

  } else if(!connected) {
    if(state != STATE_DISCONNECTED) {

      syslog(LOG_DEBUG, "%s: Physical disconnect detected\n", ifname);

      state = STATE_DISCONNECTED;
      close_socket(sock);

      run_hook_script(hook_script_path, "down", NULL);
    }
  }

}

int open_raw_socket(char* ifname, struct sockaddr_ll* bind_addr) {

  unsigned padding;
  int sock;
  int result = -1;
  const char *msg;
  int ifindex;
  const unsigned char broadcast_mac[] = {0xff,0xff,0xff,0xff,0xff,0xff};

  sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (sock < 0) {
    syslog(LOG_DEBUG, "error creating socket");
    exit(1);
	}

  memset(bind_addr, 0, sizeof(struct sockaddr_ll));

	bind_addr->sll_family = AF_PACKET;
	bind_addr->sll_protocol = htons(ETH_P_IP);
	bind_addr->sll_halen = 6;
	memcpy(bind_addr->sll_addr, broadcast_mac, 6);

  ifindex = ifindex_from_ifname(sock, "eth0\0");
  if(ifindex < 0) {
    syslog(LOG_DEBUG, "error getting ifindex\n");
    exit(1);
  }

	bind_addr->sll_ifindex = ifindex;

	if(bind(sock, (struct sockaddr*) bind_addr, sizeof(struct sockaddr_ll)) < 0) {
    syslog(LOG_DEBUG, "error calling bind()");
    exit(1);
	}

  if(verbose) {
    syslog(LOG_DEBUG, "Socket opened\n");
  }

  return sock;
}

int open_socket(char* ifname, struct sockaddr_in* bind_addr) {
  int sock;
  int sockmode;
  int broadcast_perm;

  if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    syslog(LOG_DEBUG, "creating socket failed");
    return -1;
  }

  if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)+1) < 0) {
    syslog(LOG_DEBUG, "binding to device failed");
    return -1;
  }

  sockmode = fcntl(sock, F_GETFL, 0);
  if(sockmode < 0) {
    syslog(LOG_DEBUG, "error getting socket mode");
    return -1;
  }
  
  if(fcntl(sock, F_SETFL, sockmode | O_NONBLOCK) < 0) {
    syslog(LOG_DEBUG, "failed to set non-blocking mode for socket");
    return -1;
  }

  broadcast_perm = 1;
  if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcast_perm, sizeof(broadcast_perm)) < 0) {
    syslog(LOG_DEBUG, "setting broadcast permission on socket failed");
    return -1;
  }
  
  if(bind(sock, (struct sockaddr*) bind_addr, sizeof(struct sockaddr_in)) < 0) {
    syslog(LOG_DEBUG, "failed to bind udp socket");
    return -1;
  }
  
  return sock;
}

int close_socket(int sock) {
  return close(sock);
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
  int nlsock;
  int num_ready;
  int max_fd;
  struct timeval timeout;
  time_t last_request = 0;
  int c;
  int log_option = 0;

  state = STATE_DISCONNECTED;
  
  if(argc <= 0) {
    usagefail(NULL);
    exit(1);
  }

  while((c = getopt(argc, argv, "s:c:k:fvh")) != -1) {
    switch (c) {
    case 's':
      hook_script_path = optarg;
      break;
    case 'c':
      ssl_cert_path = optarg;
      break;
    case 'f': 
      log_option |= LOG_PERROR;
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

  // Open the syslog facility
  openlog("notdhcpclient", log_option, LOG_DAEMON);

  listen_ifname = argv[optind];

  nlsock = netlink_open_socket();
  if(nlsock < 0) {
    syslog(LOG_ERR, "Fatal error: Could not open netlink socket\n");
    exit(1);
  }

  if(netlink_send_request(nlsock) < 0) {
    syslog(LOG_DEBUG, "Fatal error: Failed to send netlink request");
    exit(1);
  }
  
  for(;;) {
    FD_ZERO(&fdset);

    if(state == STATE_CONNECTED) {
      FD_SET(sock, &fdset);
    }

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
      syslog(LOG_DEBUG, "error during select");
    }

    if(FD_ISSET(sock, &fdset)) {
      /*
      while(handle_incoming(sock)) {
        // nothing here
      }
      */
    }

    if(FD_ISSET(nlsock, &fdset)) {
      netlink_handle_incoming(nlsock, physical_ethernet_state_change);
    }

    if((state == STATE_CONNECTED) && (time(NULL) - last_request >= SEND_REQUEST_EVERY)) {
      syslog(LOG_DEBUG, "Sending request\n");
      send_request(sock_raw, &bind_addr_raw);
      last_request = time(NULL);
    }
  }

  
  return 0;
}
