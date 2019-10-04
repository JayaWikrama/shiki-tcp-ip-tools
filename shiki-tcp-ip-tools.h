#ifndef __SHIKI_TCP_IP_TOOLS__
#define __SHIKI_TCP_IP_TOOLS__

struct stcp_sock_data{
    int socket_f, connection_f;
};

struct stcp_sock_data stcp_client_init(char *ADDRESS, int PORT, int infinite_retry_mode);
struct stcp_sock_data stcp_server_init(char *ADDRESS, int PORT, int infinite_retry_mode);
int stcp_send_data(struct stcp_sock_data com_data, char* buff);
int stcp_recv_data(struct stcp_sock_data com_data, char* buff, int size_set);

#endif