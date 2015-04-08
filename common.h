
int run_hook_script(char* hook_script_path, ...);

int raw_udp_broadcast(int sock, void* buffer, size_t len, uint16_t source_port, uint16_t dest_port);
