#ifndef __SHIKI_TCP_IP_TOOLS__
#define __SHIKI_TCP_IP_TOOLS__

#define INFINITE_RETRY 1
#define WITHOUT_RETRY 0
#define STCP_DEBUG_ON 1
#define STCP_DEBUG_OFF 0

struct stcp_sock_data{
    int socket_f, connection_f;
};


/*
  stcp_client_init
  stcp_server_init

  ADDRESS : your IP ADDRESS (127.0.0.1 for local purpose, server address for general purpose)
  PORT : port that will be used
  infinite_retry_mode : fill with INFINITE_RETRY for infinite init purpose (end when init success)
  debug_mode : parameter for enable or disable debug information
*/
struct stcp_sock_data stcp_client_init(char *ADDRESS, int PORT, int infinite_retry_mode, int debug_mode);
struct stcp_sock_data stcp_server_init(char *ADDRESS, int PORT, int infinite_retry_mode, int debug_mode);

/*
  stcp_send_data
  stcp_recv_data

  com_data : based on init process
  buff : buffer that will be send or receive
  size_set : length of buffer (you can use strlen(buffer))

  return success : >= 0
  return fail : -1
*/
int stcp_send_data(struct stcp_sock_data com_data, char* buff, int size_set);
int stcp_recv_data(struct stcp_sock_data com_data, char* buff, int size_set);


void stcp_close(struct stcp_sock_data init_data);
#endif