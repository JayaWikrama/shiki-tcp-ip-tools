#ifndef __SHIKI_TCP_IP_TOOLS__
#define __SHIKI_TCP_IP_TOOLS__

#include <openssl/ssl.h>
#include <stdint.h>

#define INFINITE_RETRY 1
#define WITHOUT_RETRY 0
#define STCP_DEBUG_ON 1
#define STCP_DEBUG_OFF 0

struct stcp_sock_data{
  int socket_f, connection_f;
  SSL *ssl_connection_f;
};

typedef enum {
  STCP_REQ_COMPLETE = 0,
  STCP_REQ_HEADER_ONLY = 1,
  STCP_REQ_CONTENT_ONLY = 2
} stcp_request_type;

typedef enum{
  STCP_SET_TIMEOUT = 0,
  STCP_SET_DEBUG_MODE = 1,
  STCP_SET_SIZE_PER_RECV = 2,
  STCP_SET_INFINITE_MODE_RETRY = 3
} stcp_setup_parameter;


int8_t stcp_setup(stcp_setup_parameter _setup_parameter, int16_t _value);

/*
  stcp_client_init
  stcp_server_init
  stcp_ssl_client_init

  ADDRESS : your IP ADDRESS (127.0.0.1 for local purpose, server address for general purpose) or URL
  PORT : port that will be used
  infinite_retry_mode : fill with INFINITE_RETRY for infinite init purpose (end when init success)
  debug_mode : parameter for enable or disable debug information
*/
struct stcp_sock_data stcp_client_init(char *ADDRESS, uint16_t PORT);
struct stcp_sock_data stcp_server_init(char *ADDRESS, uint16_t PORT);
struct stcp_sock_data stcp_ssl_client_init(char *ADDRESS, uint16_t PORT);
/*
  stcp_send_data
  stcp_recv_data
  stcp_ssl_send_data
  stcp_ssl_recv_data

  com_data : based on init process
  buff : buffer that will be send or receive
  size_set : length of buffer (you can use strlen(buffer))

  return success : >= 0
  return fail : -1
*/
int16_t stcp_send_data(struct stcp_sock_data com_data, char* buff, int16_t size_set);
int16_t stcp_recv_data(struct stcp_sock_data com_data, char* buff, int16_t size_set);
int16_t stcp_ssl_send_data(struct stcp_sock_data com_data, char* buff, int16_t size_set);
int16_t stcp_ssl_recv_data(struct stcp_sock_data com_data, char* buff, int16_t size_set);

int8_t stcp_url_parser(char *_url, char *_host, char *_protocol, char *_end_point, uint16_t *_port);
char *stcp_http_request(char *_req_type, char *_url, char *_header, char *_content, stcp_request_type _request_type);

void stcp_close(struct stcp_sock_data *init_data);
void stcp_ssl_close(struct stcp_sock_data *init_data);
#endif