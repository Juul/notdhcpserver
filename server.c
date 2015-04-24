#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h> 
#include <syslog.h>
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

#include "crc32.h"
#include "common.h"
#include "protocol.h"
#include "phyconnect.h"

// structs below

struct interface {
  char* ifname;
  char* ip;
  char* netmask;
  int sock;
  int sock_l2;
  struct sockaddr_in addr;
  struct sockaddr_ll addr_l2;
  char password[PASSWORD_LENGTH + 1];
  int state;
  struct interface* next;
};

#define STATE_STOPPED (0)
#define STATE_LISTENING (1)
#define STATE_GOT_ACK (2)

// global variables below

int verbose = 0;
struct interface* interfaces = NULL;
char* ssl_cert_path = NULL;
char* ssl_cert = NULL;
char* ssl_key_path = NULL;
char* ssl_key = NULL;
char* hook_script_path = NULL;

// functions declarations below

int seed_prng() {
  struct timeval time;
  
  if(gettimeofday(&time, NULL) < 0) {
    syslog(LOG_ERR, "seeding prng failed");
    return -1;
  }
  srand(time.tv_usec * time.tv_sec);
}

// writes a null-terminated password string
// of size (len - 1) to a buffer of size len
// (assumes that buffer has already been allocated)
void generate_password(char* buffer, int len) {
  const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJK";
  int key;

  buffer[--len] = '\0';

  while(len) {
    key = rand() % (int) (sizeof(charset) - 1);
    buffer[len - 1] = charset[key];
    len--;
  }

  return;
}

int broadcast_packet(int sock, void* buffer, size_t len) {
  struct sockaddr_in broadcast_addr;
  int sent = 0;
  int ret;
  int max;

  memset(&broadcast_addr, 0, sizeof(broadcast_addr));
  broadcast_addr.sin_family = AF_INET;
  broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
  broadcast_addr.sin_port = htons(CLIENT_PORT);

  while(sent < len) {
    ret = sendto(sock, buffer + sent, len, 0, (struct sockaddr *) &broadcast_addr, sizeof(broadcast_addr));
    if(ret < 0) {
      return ret;
    }
    sent += ret;
  }

  return 0;
}

int send_response(struct interface* iface) {
  struct response resp;
  void* sendbuf;
  int response_size;
  int cert_size;
  int key_size;
  int ret;

  resp.type = htonl(RESPONSE_TYPE);
  resp.lease_ip = htonl(inet_addr(iface->ip));
  resp.lease_netmask = htonl(inet_addr(iface->netmask));
  strncpy((char*) &(resp.password), iface->password, PASSWORD_LENGTH + 1);

  if(!ssl_cert || !ssl_key) {
    resp.cert_size = 0;
    resp.key_size = 0;

    if(verbose) {
      printf("%s: sending response (without ssl certificate)\n", iface->ifname);
      fflush(stdout);
    }
    return broadcast_layer2(iface->sock_l2, (void*) &resp, sizeof(resp), SERVER_PORT, CLIENT_PORT, &(iface->addr_l2));
  }

  cert_size = strlen(ssl_cert) + 1;
  key_size = strlen(ssl_key) + 1;

  resp.cert_size = htonl(cert_size);
  resp.key_size = htonl(key_size);

  sendbuf = malloc(sizeof(resp) + cert_size + key_size);
  memcpy(sendbuf, &resp, sizeof(resp));

  // copy ssl cert into buffer
  memcpy(sendbuf+sizeof(resp), ssl_cert, cert_size);

  // ensure null-terminated key string
  ((char*) sendbuf)[sizeof(resp) + cert_size - 1] = '\0';

  // copy ssl key into buffer
  memcpy(sendbuf + sizeof(resp) + cert_size, ssl_key, key_size);

  // ensure null-terminated key string
  ((char*) sendbuf)[sizeof(resp) + cert_size + key_size - 1] = '\0';

  response_size = sizeof(resp) + cert_size + key_size;;

  if(verbose) {
    printf("%s: sending response (with ssl certificate)\n", iface->ifname);
    fflush(stdout);
  }
  ret = broadcast_layer2(iface->sock_l2, sendbuf, response_size, SERVER_PORT, CLIENT_PORT, &(iface->addr_l2));

  free(sendbuf);

  return ret;
}


int handle_incoming(struct interface* iface) {
  struct request req;
  ssize_t ret;
  socklen_t addrlen = sizeof(iface->addr);
  
  ret = recvfrom(iface->sock, &req, sizeof(req), 0, (struct sockaddr*) &(iface->addr), &addrlen);
  if(ret < 0) {
    if((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
      return 0;
    }
  }

  // didn't receive a full request, so just wait for next one to arrive
  if(ret < sizeof(req)) {
    return 1;
  }

  if(ret == 0) {
    return 1;
  }

  req.type = ntohl(req.type);

  if(req.type == REQUEST_TYPE_GETLEASE) {
    if(verbose) {
      printf("%s: Received lease request\n", iface->ifname);
      fflush(stdout);
    }
    generate_password(iface->password, PASSWORD_LENGTH + 1);

    send_response(iface);
    return 1;
  }

  if(req.type == REQUEST_TYPE_ACK) {
    if(iface->state == STATE_GOT_ACK) {
      if(verbose) {
        printf("%s: Received redundant ACK\n", iface->ifname);
        fflush(stdout);
      }
      return 1;
    }
    if(verbose) {
      printf("%s: Received ACK\n", iface->ifname);
      fflush(stdout);
    }
    iface->state = STATE_GOT_ACK;
    if(verbose) {
      printf("%s: Running up hook script\n", iface->ifname);
      fflush(stdout);
    }
    run_hook_script(hook_script_path, iface->ifname, "up", NULL);
    return 1;
  }

  if(verbose) {
    printf("%s: Got unknown request type\n", iface->ifname);
    fflush(stdout);
  }
  
  return 1;
}

// call with e.g. usage(argv[0], stdin) or usage(argv[0], stderr)
void usage(char* command_name, FILE* out) {
  char default_command_name[] = "notdhcpserver";
  if(!command_name) {
    command_name = (char*) &default_command_name;
  }
  fprintf(out, "Usage: %s [-v] ifname=ip/netmask [ifname2=ip2/netmask2 ...]\n", command_name);
  fprintf(out, "\n");
  fprintf(out, "  -s: Hook script. See readme for more info.\n");  
  fprintf(out, "  -f: Do not write to stderror, only to system log.\n");  
  fprintf(out, "  -c ssl_cert: Path to SSL cert to send to client\n");
  fprintf(out, "  -k ssl_key: Path to SSL key to send to client\n");
  fprintf(out, "  -v: Enable verbose mode\n");
  fprintf(out, "  -h: This help text\n");
  fprintf(out, "\n");
  fprintf(out, "For each interface where you want nothcpserver to hand out an IP \"lease\"\n");
  fprintf(out, "specify an interface+ip pair. E.g:\n");
  fprintf(out, "\n");
  fprintf(out, "  %s eth0.2=100.64.0.2/255.255.255.192 eth0.3=100.64.0.3/255.255.255.192\n", command_name);
  fprintf(out, "\n");
  fflush(out);
}

void usagefail(char* command_name) {
  fprintf(stderr, "Error: Missing required command-line arguments.\n\n");
  usage(command_name, stderr);
  return;
}

struct interface* new_interface() {
  struct interface* iface = (struct interface*) malloc(sizeof(struct interface));

  return iface;
}

// add interface to linked list and return the previous end of the linked list
struct interface* add_interface(struct interface* iface) {
  struct interface* cur = interfaces;

  iface->next = 0;
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

int stop_monitor_interface(struct interface* iface) {
  iface->state = STATE_STOPPED;
  return close(iface->sock);
}

int monitor_interface(struct interface* iface) {

  if(iface->sock < 0) {
    syslog(LOG_ERR, "opening socket failed on %s\n", iface->ifname);
    return -1;
  }

  iface->sock_l2 = open_socket_layer2(iface->ifname, &(iface->addr_l2));
  if(iface->sock_l2 < 0) {
    syslog(LOG_ERR, "opening layer 2 socket failed on %s\n", iface->ifname);
    return -1;
  }

  iface->state = STATE_LISTENING;

  if(verbose) {
    syslog(LOG_DEBUG, "Listening on interface %s:\n", iface->ifname);
    syslog(LOG_DEBUG, "  client IP: %s\n", iface->ip);
    syslog(LOG_DEBUG, "  client netmask %s\n\n", iface->netmask);
  }

  return 0;
}

int parse_arg(char* arg) {

  struct interface* iface;
  int arglen = strlen(arg);
  int i;
  int ip_offset;
  int netmask_offset;
  int ip_len;
  int netmask_len;

  iface = new_interface();

  for(i=0; i < arglen; i++) {

    if(arg[i] == '=') {
      iface->ifname = (char*) malloc(i+1);
      memcpy(iface->ifname, arg, i);
      iface->ifname[i] = '\0';
      ip_offset = i + 1;
    }
    if(arg[i] == '/') {
      if(!iface->ifname) {
        return -1;
      }
      
      ip_len = i - ip_offset;
      iface->ip = (char*) malloc(ip_len + 1);
      memcpy(iface->ip, arg + ip_offset, ip_len);
      iface->ip[ip_len] = '\0';
      netmask_offset = i + 1;

      netmask_len = strlen(arg) - netmask_offset;
      iface->netmask = (char*) malloc(netmask_len + 1);
      memcpy(iface->netmask, arg + netmask_offset, netmask_len);
      iface->netmask[netmask_len] = '\0';

      break;
    }
  }

  if(!iface->ifname || !iface->ip || !iface->netmask) {
    fprintf(stderr, "Failed to parse argument: %s\n", arg);
    return -1;
  }

  if(monitor_interface(iface) < 0) {
    return -1;
  }
  
  add_interface(iface);

  return 0;
}


int parse_args(int argc, char** argv) {
  
  int i;
  for(i=0; i < argc; i++) {
    if(parse_arg(argv[i]) < 0) {
      return -1;
    }
  }

  return 0;
}

char* load_file(char* path, int size) {
  FILE* f;
  char* buf = malloc(size);
  size_t bytes_read;

  f = fopen(path, "r");
  if(!f) {
    syslog(LOG_ERR, "Opening certificate or key file failed");
    return NULL;
  }

  bytes_read = fread(buf, 1, size, f);
  if(ferror(f)) {
    syslog(LOG_ERR, "Error reading certificate or key file");
    return NULL;
  }
  if(bytes_read <= 0) {
    syslog(LOG_ERR, "Reading certificate or key file failed. Is the file empty?\n");
    return NULL;
  }

  if(fclose(f) == EOF) {
    syslog(LOG_ERR, "Closing certificate file failed.\n");
    return NULL;
  }

  if(verbose) {
    printf("Loaded SSL certificate from %s\n", path);
  }

  return buf;
}


void physical_ethernet_state_change(char* ifname, int connected) {
  struct interface* iface;

  // check if we are monitoring this interface
  iface = interfaces;
  do {
    if(strcmp(iface->ifname, ifname) == 0) {
      if(connected) { // interface up event
        // if interface was stopped then resume listening
        if(iface->state == STATE_STOPPED) {
          if(verbose) {
            printf("%s: Physical connection detected\n", ifname);
            fflush(stdout);
          }
          if(monitor_interface(iface) < 0) {
            return;
          }
          return;
        }
      } else { // interface down event
        // if interface was listening then stop listening and run down hook
        if(iface->state != STATE_STOPPED) {
          if(stop_monitor_interface(iface) < 0) {
            return;
          }
          if(verbose) {
            syslog(LOG_WARNING, "%s: Physical disconnect detected\n", ifname);
          }
          run_hook_script(hook_script_path, iface->ifname, "down", NULL);
        }
        return;
      }
    }
  } while(iface = iface->next);
  
}

int main(int argc, char** argv) {

  fd_set fdset;
  int nlsock;
  int max_fd;
  int num_ready;
  extern int optind;
  struct interface* iface;
  int c;
  int log_option = LOG_PERROR;

  if(argc <= 0) {
    usagefail(NULL);
    exit(1);
  }

  while((c = getopt(argc, argv, "c:k:s:vfh")) != -1) {
    switch (c) {
    case 's':
      hook_script_path = optarg;
      break;
    case 'f': 
      log_option = 0;
      break;
    case 'c':
      ssl_cert_path = optarg;
      ssl_cert = load_file(optarg, MAX_CERT_SIZE - 1);
      if(!ssl_cert) {
        exit(1);
      }
      break;
    case 'k':
      ssl_key_path = optarg;
      ssl_key = load_file(optarg, MAX_KEY_SIZE - 1);
      if(!ssl_key) {
        exit(1);
      }
      break;
    case 'v': 
      printf("Verbose mode enabled\n");
      fflush(stdout);
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

  if((ssl_cert && !ssl_key) || (!ssl_cert && ssl_key)) {
    syslog(LOG_ERR, "If you supply a certificate path then you must also supply a key path and vice versa.\n");
    usagefail(argv[0]);
    exit(1);
  }

  if(seed_prng() < 0) {
    exit(1);
  }         

  nlsock = netlink_open_socket();
  if(nlsock < 0) {
    syslog(LOG_ERR, "could not open netlink socket\n");
    exit(1);
  }

  if(parse_args(argc - optind, argv + optind) < 0) {
    exit(1);
  }

  for(;;) {

    // initialize fdset
    FD_ZERO(&fdset);

    max_fd = 0;
    iface = interfaces;
    do {
      // skip ifaces that already got an ACK
      if(iface->state != STATE_LISTENING) {
        continue;
      }
      FD_SET(iface->sock, &fdset);
      if(iface->sock > max_fd) {
        max_fd = iface->sock;
      }
    } while(iface = iface->next);

    FD_SET(nlsock, &fdset);
    if(nlsock > max_fd) {
      max_fd = nlsock;
    }

    if((num_ready = select(max_fd + 1, &fdset, NULL, NULL, NULL)) < 0) {
      if(errno == EINTR) {
        syslog(LOG_WARNING, "huh?\n");// TODO when does this happen
        continue;
      }
      syslog(LOG_ERR, "error during select");
    }

    if(FD_ISSET(nlsock, &fdset)) {
      netlink_handle_incoming(nlsock, physical_ethernet_state_change);
    }
    iface = interfaces;
    do {
      if(FD_ISSET(iface->sock, &fdset)) {
        while(handle_incoming(iface)) {
          // nothing here
        }
        
      }
    } while(iface = iface->next);
  }  

  return 0;
}
