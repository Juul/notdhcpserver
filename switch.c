#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h> 
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <sys/socket.h>

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/switch.h>
#include "swlib.h"

#include "swlib/swlib.h"

#include "switch.h"

struct switch_dev* swdev = NULL;
struct switch_attr *link_attr;
struct switch_attr *ports_attr;

// returns 1 on switch found
// returns 0 on no switch found
// return -1 on error
int switch_init(char* listen_ifname) {
  swdev = swlib_connect(listen_ifname);
  if(!swdev) {
    return 0;
  }
  
  swlib_scan(swdev);

	link_attr = swlib_lookup_attr(swdev, SWLIB_ATTR_GROUP_PORT, "link");
  if(!link_attr) {
    syslog(LOG_ERR, "Could not find switch port link attribute");
    return -1;
  }
  if(link_attr->type != SWITCH_TYPE_STRING) {
    syslog(LOG_ERR, "Switch port link attribute has unexpected type");
    return -1;
  }

	ports_attr = swlib_lookup_attr(swdev, SWLIB_ATTR_GROUP_VLAN, "ports");
  if(!ports_attr) {
    syslog(LOG_ERR, "Could not find switch vlan ports attribute");
    return -1;
  }
  if(ports_attr->type != SWITCH_TYPE_PORTS) {
    syslog(LOG_ERR, "Switch vlan ports attribute has unexpected type");
    return -1;
  }

  return 1;
}


// Takes a network interface device name like eth0.2
// and assumes that the VLAN id is 2
// then calls switch_vlan_link_status with that VLAN id
int switch_ifname_link_status(char* ifname) {
  int i;
  int len = strlen(ifname);
  int vlan_id;
  
  for(i=0; i < len - 1; i++) {
    if(ifname[i] == '.') {
      vlan_id = atoi(ifname + i + 1);
      return switch_vlan_link_status(vlan_id);
    }
  }
  return -1;
}

// Takes a VLAN id 
// and returns the status of the first port with that VLAN id
// unless that port is 0, in which case it returns the status of the second port
// This is because 0 is the CPU port for which status is irrelevant.
// Return value same as switch_port_link_status
int switch_vlan_link_status(int vlan_id) {

	struct switch_val val;
  int port;
  int i;
  
  val.port_vlan = vlan_id;

  if(swlib_get_attr(swdev, ports_attr, &val) < 0) {
    return -1;
  }

  for(i = 0; i < val.len; i++) {
    port = val.value.ports[i].id;
    if(port != 0) {
      return switch_port_link_status(port);
    }
  }
  
  return -1;
}

// Takes the switch port number as argument
// Returns 0 on link down and 1 on link up
int switch_port_link_status(int port) {

	struct switch_val val;
  char* ret;
  
  val.port_vlan = port;

  if(swlib_get_attr(swdev, link_attr, &val) < 0) {
    return -1;
  }

  ret = strstr(val.value.s, "link:up");

  /*
   * "When getting string attributes, val->value.s must be freed by the caller"
   * (see swlib/swlib.h)
   */
  free(val.value.s);

  if(ret) {
    return 1;
  }

  return 0;
}


