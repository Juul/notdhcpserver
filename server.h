#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include "protocol.h"

#define STATE_STOPPED (0)
#define STATE_LISTENING (1)
#define STATE_GOT_ACK (2)

struct interface {
  char* ifname;
  int vlan;
  char* ip;
  int netmask;
  int sock;
  int sock_l2;
  struct sockaddr_in addr;
  struct sockaddr_ll addr_l2;
  char password[PASSWORD_LENGTH + 1];
  int state;
  time_t time_passed;
  time_t last_contact;
  struct interface* next;
};
