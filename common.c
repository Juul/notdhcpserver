#include <unistd.h> 
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "common.h"

int ifindex_from_ifname(int sock, char* ifname) {

  struct ifreq ifr;
  size_t len = strlen(ifname);

  if(len < sizeof(ifr.ifr_name)) {
    memcpy(ifr.ifr_name, ifname, len);
    ifr.ifr_name[len] = '\0';
  } else {
    return -1;
  }

  if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    return -1;
  }
  return ifr.ifr_ifindex;
}

unsigned short calc_checksum(unsigned char *data, int len) {
    long sum = 0;
    unsigned short *temp = (unsigned short *)data;

    while(len > 1){
        sum += *temp++;
        if(sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if(len) {
      sum += (unsigned short) *((unsigned char *)temp);
    }

    while(sum>>16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

int open_socket(char* ifname, struct sockaddr_in* bind_addr, unsigned short listen_port) {
  int sock;
  int sockmode;
  int one = 1;

  if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("creating socket failed");
    return -1;
  }

  if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)+1) < 0) {
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

  if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof(one)) < 0) {
    perror("setting SO_REUSEADDR on socket failed");
    return -1;
  }

  /*
  if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *) &one, sizeof(one)) < 0) {
    perror("setting SO_REUSEPORT on socket failed");
    return -1;
  }
  */

  if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &one, sizeof(one)) < 0) {
    perror("setting broadcast permission on socket failed");
    return -1;
  }

  memset(bind_addr, 0, sizeof(bind_addr));
  bind_addr->sin_family = AF_INET;
  bind_addr->sin_addr.s_addr = inet_addr("255.255.255.255");
  bind_addr->sin_port = htons(listen_port);
  
  if(bind(sock, (struct sockaddr*) bind_addr, sizeof(struct sockaddr_in)) < 0) {
    perror("failed to bind udp socket");
    return -1;
  }
  
  return sock;
}

int close_socket(int sock) {
  return close(sock);
}

int open_socket_layer2(char* ifname, struct sockaddr_ll* bind_addr) {

  unsigned padding;
  int sock;
  int result = -1;
  const char *msg;
  int ifindex;
  int one = 1;
  const unsigned char broadcast_mac[] = {0xff,0xff,0xff,0xff,0xff,0xff};

  sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (sock < 0) {
    perror("error creating socket");
    exit(1);
	}

  if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof(one)) < 0) {
    perror("setting SO_REUSEADDR on layer2 socket failed");
    return -1;
  }

  /*
  if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *) &one, sizeof(one)) < 0) {
    perror("setting SO_REUSEPORT on layer2 socket failed");
    return -1;
  }
  */
  memset(bind_addr, 0, sizeof(struct sockaddr_ll));

	bind_addr->sll_family = AF_PACKET;
	bind_addr->sll_protocol = htons(ETH_P_IP);
	bind_addr->sll_halen = 6;
	memcpy(bind_addr->sll_addr, broadcast_mac, 6);

  ifindex = ifindex_from_ifname(sock, ifname);
  if(ifindex < 0) {
    printf("error getting ifindex\n");
    exit(1);
  }

	bind_addr->sll_ifindex = ifindex;

	if(bind(sock, (struct sockaddr*) bind_addr, sizeof(struct sockaddr_ll)) < 0) {
    perror("error calling bind()");
    exit(1);
	}

  return sock;
}

int broadcast_layer2(int sock, void* buffer, size_t len, uint16_t src_port, uint16_t dest_port, struct sockaddr_ll* dest_addr) {
  //  struct sockaddr_in dest_addr;
  struct iphdr* ip_header;
  struct udphdr* udp_header;
  void* payload;
  void* alt;
  size_t packet_size;
  ssize_t sent = 0;
  ssize_t ret;

  packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + len;

  void* data = (void*) malloc(packet_size);
  if(!data) {
    return -1;
  }

  bzero(data, packet_size);

  ip_header = data;
  udp_header = data + sizeof(struct iphdr);
  payload = data + sizeof(struct iphdr) + sizeof(struct udphdr);

  memcpy(payload, buffer, len);

  ip_header->version = 4;
  ip_header->protocol = IPPROTO_UDP;
  ip_header->daddr = INADDR_ANY;
  ip_header->daddr = INADDR_BROADCAST;
  ip_header->ihl = sizeof(struct iphdr) >> 2;
  ip_header->ttl = IPDEFTTL;
  ip_header->tot_len = htons(packet_size);
  ip_header->check = calc_checksum((unsigned char *) ip_header, sizeof(struct iphdr));

  // TODO add udp checksum
  udp_header->source = htons(src_port);
  udp_header->dest = htons(dest_port);
  udp_header->check = htons(0);
  udp_header->len = htons(sizeof(struct udphdr) + len);
  
  while(sent < packet_size) {
    ret = sendto(sock, data + sent, packet_size - sent, 0, (struct sockaddr*) dest_addr, sizeof(struct sockaddr_ll));

    if(ret < 0) {
      perror("failed to send");
      free(data);
      return ret;
    }
    sent += ret;
  }

  free(data);

  return sent - sizeof(struct iphdr) - sizeof(struct udphdr);
}


int run_hook_script(char* hook_script_path, ...) {
  va_list args;
  char* cur;
  char* cmd;
  int len;
  int i;
  int ret;

  if(!hook_script_path) {
    return;
  }

  len = strlen(hook_script_path + 1);
  
  va_start(args, hook_script_path); 
  
  while((cur = va_arg(args, char *)) != NULL) {
    len += strlen(cur) + 2;
  }
  
  va_end(args);

  cmd = malloc(len);

  va_start(args, hook_script_path); 
  
  i = 0;
  strcpy(cmd, hook_script_path);
  i += strlen(hook_script_path);
  cmd[i++] = ' ';

  while((cur = va_arg(args, char *)) != NULL) {
    strcpy(cmd + i, cur);
    i += strlen(cur);
    cmd[i++] = ' ';
  }

  cmd[i-1] = '\0';
    
  va_end(args);

  ret = system(cmd);

  free(cmd);

  return ret;
}
