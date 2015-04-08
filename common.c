
#include <unistd.h> 
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

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

unsigned short ComputeChecksum(unsigned char *data, int len)
{
    long sum = 0;  /* assume 32 bit long, 16 bit short */
    unsigned short *temp = (unsigned short *)data;

    while(len > 1){
        sum += *temp++;
        if(sum & 0x80000000)   /* if high order bit set, fold */
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if(len)       /* take care of left over byte */
        sum += (unsigned short) *((unsigned char *)temp);

    while(sum>>16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

int raw_udp_broadcast(int sock, void* buffer, size_t len, uint16_t src_port, uint16_t dest_port, struct sockaddr_ll* dest_addr) {
  //  struct sockaddr_in dest_addr;
  struct iphdr* ip_header;
  struct udphdr* udp_header;
  void* payload;
  size_t packet_size;
  ssize_t sent = 0;
  ssize_t ret;

  packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + len;

  void* data = (void*) malloc(packet_size);
  if(!data) {
    return -1;
  }

  memset(data, 0, packet_size);

  ip_header = data;
  udp_header = data + sizeof(struct iphdr);
  payload = udp_header + sizeof(struct udphdr);
  memcpy(payload, buffer, len);

  /*
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
  dest_addr.sin_port = htons(dest_port);
  */

  ip_header->version = 4;
  ip_header->protocol = IPPROTO_UDP;
  inet_pton(AF_INET, "0.0.0.0", &(ip_header->saddr));
  ip_header->daddr = INADDR_BROADCAST;
  ip_header->ihl = sizeof(struct iphdr) >> 2;
  ip_header->ttl = IPDEFTTL;
  ip_header->tot_len = htons(packet_size);
  ip_header->check = ComputeChecksum((unsigned char *) ip_header, sizeof(struct iphdr));

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
