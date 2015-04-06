struct request {
  uint32_t type;
};

struct response {
  uint32_t type;
  uint32_t lease_ip;
  uint32_t lease_netmask;
  uint32_t cert_size;
  uint32_t key_size;
};
