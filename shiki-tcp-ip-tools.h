#ifndef __SHIKI_TCP_IP_TOOLS__
#define __SHIKI_TCP_IP_TOOLS__

#define __STCP_PING__
#define __STCP_SSL__

#include <stdint.h>
#ifdef __STCP_SSL__
  #include <openssl/ssl.h>
#endif

#define INFINITE_RETRY 1
#define WITHOUT_RETRY 0
#define STCP_DEBUG_ON 1
#define STCP_DEBUG_OFF 0

#define STCP_MAX_LENGTH_FILE_NAME 16

struct stcp_sock_data{
  int socket_f, connection_f;
  #ifdef __STCP_SSL__
    SSL *ssl_connection_f;
  #endif
};

#ifdef __STCP_PING__
  struct stcp_ping_summary{
    int8_t state;
    uint16_t tx_counter;
    uint16_t rx_counter;
    uint16_t max_rtt;
    uint16_t min_rtt;
    uint16_t avg_rtt;
    uint8_t packet_loss;
    uint32_t time_counter;
  };
#endif

typedef enum {
  STCP_REQ_COMPLETE = 0,
  STCP_REQ_HEADER_ONLY = 1,
  STCP_REQ_CONTENT_ONLY = 2,
  STCP_REQ_HTTP_STATUS_ONLY = 3,
  STCP_REQ_DOWNLOAD_CONTENT = 4
} stcp_request_type;

typedef enum{
  STCP_SET_TIMEOUT_IN_SEC = 0,
  STCP_SET_TIMEOUT_IN_MILLISEC = 1,
  STCP_SET_DEBUG_MODE = 2,
  STCP_SET_SIZE_PER_RECV = 3,
  STCP_SET_INFINITE_MODE_RETRY = 4
} stcp_setup_parameter;

void stcp_view_version();
long stcp_get_version(char *_version);
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

#ifdef __STCP_SSL__
  struct stcp_sock_data stcp_ssl_client_init(char *ADDRESS, uint16_t PORT);
#endif

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
int16_t stcp_send_data(struct stcp_sock_data com_data, unsigned char* buff, int16_t size_set);
int16_t stcp_recv_data(struct stcp_sock_data com_data, unsigned char* buff, int16_t size_set);

#ifdef __STCP_SSL__
  int16_t stcp_ssl_send_data(struct stcp_sock_data com_data, unsigned char* buff, int16_t size_set);
  int16_t stcp_ssl_recv_data(struct stcp_sock_data com_data, unsigned char* buff, int16_t size_set);
#endif

int8_t stcp_url_parser(char *_url, char *_host, char *_protocol, char *_end_point, uint16_t *_port);
char *stcp_http_content_generator(uint16_t _sizeof_content, char *_content_format, ...);
unsigned char *stcp_http_request(char *_req_type, char *_url, char *_header, char *_content, stcp_request_type _request_type);

void stcp_close(struct stcp_sock_data *init_data);

#ifdef __STCP_SSL__
  void stcp_ssl_close(struct stcp_sock_data *init_data);
#endif

/* ADDITIONAL PURPOSE */
#ifdef __STCP_PING__
  struct stcp_ping_summary stcp_ping(char *ADDRESS, uint16_t NUM_OF_PING);
#endif
#endif