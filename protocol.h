
#define PASSWORD_LENGTH (32)

struct request {
  uint32_t crc;
  uint32_t type;
};

struct response {
  uint32_t crc;
  uint32_t type;
  uint32_t lease_ip;
  uint32_t lease_netmask;
  uint32_t cert_size;
  uint32_t key_size;
  char password[PASSWORD_LENGTH + 1];
};

#define SERVER_PORT (4242)
#define CLIENT_PORT (4343)

#define REQUEST_TYPE_GETLEASE (42)
#define RESPONSE_TYPE (43)
#define REQUEST_TYPE_ACK (44)

// how big is an ssl cert allowed to be (in bytes)
#define MAX_CERT_SIZE (16384)

// how big is an ssl key allowed to be (in bytes)
#define MAX_KEY_SIZE (16384)

// how big is a response allowed to be (in bytes)
#define MAX_RESPONSE_SIZE (sizeof(struct response) + MAX_CERT_SIZE + MAX_KEY_SIZE)
