#ifndef __SHIKI_TCP_IP_TOOLS__
#define __SHIKI_TCP_IP_TOOLS__

#define __STCP_PING__
#define __STCP_SSL__
#define __STCP_WEBSERVER__

#include <stdint.h>
#ifdef __STCP_SSL__
  #include <openssl/ssl.h>
  typedef enum {
    STCP_SSL_CERT_TYPE_FILE = 0x00,
    STCP_SSL_CERT_TYPE_TEXT = 0x01,
    STCP_SSL_KEY_TYPE_FILE = 0x02,
    STCP_SSL_KEY_TYPE_TEXT = 0x03,
    STCP_SSL_CACERT_TYPE_FILE = 0x04,
    STCP_SSL_CACERT_TYPE_TEXT = 0x05,
  } stcp_ssl_certkey_type;
#endif

#ifdef __STCP_WEBSERVER__
  #include "../shiki-linked-list/shiki-linked-list.h"
  typedef SHLink stcpWList;
#endif

typedef enum {
  WITHOUT_RETRY = 0x00,
  INFINITE_RETRY = 0x01,
  STCP_DEBUG_OFF = 0x04,
  STCP_DEBUG_ON = 0x03
} stcp_global_def;

#define STCP_MAX_LENGTH_FILE_NAME 16

struct stcp_sock_data{
  int socket_f, connection_f;
  #ifdef __STCP_SSL__
    SSL *ssl_connection_f;
  #endif
};

typedef struct stcp_sock_data stcpSock;

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

#ifdef __STCP_WEBSERVER__
  typedef enum{
    STCP_401_UNAUTHOIZED = 0x01,
    STCP_404_NOT_FOUND = 0x02,
    STCP_405_METHOD_NOT_ALLOWED = 0x03
  } stcp_webserver_negative_code;

  #ifdef __STCP_SSL__
  typedef enum{
    STCP_SSL_WEBSERVER_WITHOUT_VERIFY_CLIENT = 0x00,
    STCP_SSL_WEBSERVER_VERIFY_REMOTE_CLIENT = 0x01
  } stcp_ssl_webserver_verify_mode;
  #endif

  typedef struct stcp_subhead_var{
    uint16_t stcp_sub_pos;
    uint16_t stcp_sub_size;
  } stcpSHead;

  struct stcp_webserver_info{
    char *server_header;
    char *rcv_header;
    stcpSHead request;
    stcpSHead data_end_point;
    stcpSHead rcv_endpoint;
    stcpSHead rcv_content_type;
    stcpSHead rcv_acception_type;
    stcpSHead rcv_auth;
    stcpSHead rcv_cookies;
    stcpSHead rcv_connection_type;
    char *rcv_content;
    char *ipaddr;
    uint32_t content_length;
    int8_t comm_protocol;
  };

  struct stcp_webserver_header{
    char *content_type;
    char *accept_type;
  };

  typedef struct stcp_webserver_info stcpWInfo;
  typedef struct stcp_webserver_header stcpWHead;
#endif

typedef enum {
  STCP_REQ_COMPLETE = 0,
  STCP_REQ_HEADER_ONLY = 1,
  STCP_REQ_CONTENT_ONLY = 2,
  STCP_REQ_HTTP_STATUS_ONLY = 3,
  STCP_REQ_DOWNLOAD_CONTENT = 4,
  STCP_REQ_UPLOAD_FILE = 5
} stcp_request_type;

typedef enum{
  STCP_SET_TIMEOUT_IN_SEC = 0,
  STCP_SET_TIMEOUT_IN_MILLISEC = 1,
  STCP_SET_DEBUG_MODE = 2,
  STCP_SET_SIZE_PER_RECV = 3,
  STCP_SET_SIZE_PER_SEND = 4,
  STCP_SET_KEEP_ALIVE_TIMEOUT_IN_SEC = 5,
  STCP_SET_KEEP_ALIVE_TIMEOUT_IN_MILLISEC = 6,
  STCP_SET_INFINITE_MODE_RETRY = 7
  #ifdef __STCP_WEBSERVER__
  #ifdef __STCP_SSL__
  ,
  STCP_SET_WEBSERVER_VERIFY_CERT_MODE = 99
  #endif
  #endif
} stcp_setup_parameter;

void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...);

void stcp_view_version();
long stcp_get_version(char *_version);
int8_t stcp_setup(stcp_setup_parameter _setup_parameter, uint32_t _value);

#ifdef __STCP_SSL__
int8_t stcp_ssl_add_certkey(stcp_ssl_certkey_type _type, char *_host, char *_certkey);
int8_t stcp_ssl_remove_certkey(stcp_ssl_certkey_type _type, char *_host, char *_certkey);
unsigned char *stcp_ssl_get_cert(char *_host, stcp_ssl_certkey_type *_type);
unsigned char *stcp_ssl_get_key(char *_host, stcp_ssl_certkey_type *_type);
unsigned char *stcp_ssl_get_cacert(char *_host, stcp_ssl_certkey_type *_type);
void stcp_ssl_clean_certkey_collection();
#endif

/*
  stcp_client_init
  stcp_server_init
  stcp_ssl_client_init

  ADDRESS : your IP ADDRESS (127.0.0.1 for local purpose, server address for general purpose) or URL
  PORT : port that will be used
  infinite_retry_mode : fill with INFINITE_RETRY for infinite init purpose (end when init success)
  debug_mode : parameter for enable or disable debug information
*/
stcpSock stcp_client_init(char *ADDRESS, uint16_t PORT);
stcpSock stcp_server_init(char *ADDRESS, uint16_t PORT);

#ifdef __STCP_WEBSERVER__
int8_t stcp_http_webserver_init(stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList *_stcpWList);
int8_t stcp_http_webserver_add_negative_code_response(stcpWList *_stcpWList, stcp_webserver_negative_code _code_param, char *_response_content);
int8_t stcp_http_webserver_add_response(stcpWList *_stcpWList, char *_end_point, char *_response_content, char *_request_method);
int8_t stcp_http_webserver_add_response_file(stcpWList *_stcpWList, char *_end_point, char *_response_file, char *_request_method);
int8_t stcp_http_webserver_add_response_function(stcpWList *_stcpWList, char *_end_point, char *_response_function, char *_request_method);
int8_t stcp_http_webserver_set_content_type(stcpWHead *_stcpWH, char *_content_type);
int8_t stcp_http_webserver_set_accept(stcpWHead *_stcpWH, char *_accept);
int8_t stcp_http_webserver(char *ADDRESS, uint16_t PORT, uint16_t MAX_CLIENT, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList _stcpWList);

int8_t stcp_http_webserver_generate_header(stcpWInfo *_stcpWI, char *_response_header, char *_content_type, char *_acception_type, uint16_t _content_length);
int8_t stcp_http_webserver_send_file(stcpSock _init_data, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, char *_response_code, char *_file_name);
void stcp_http_webserver_stop();
#endif

#ifdef __STCP_SSL__
  stcpSock stcp_ssl_client_init(char *ADDRESS, uint16_t PORT);
#endif

/*
  stcp_send_data
  stcp_recv_data
  stcp_ssl_send_data
  stcp_ssl_recv_data

  _init_data : based on init process
  buff : buffer that will be send or receive
  size_set : length of buffer (you can use strlen(buffer))

  return success : >= 0
  return fail : -1
*/
int32_t stcp_send_data(stcpSock _init_data, unsigned char* buff, int32_t size_set);
int8_t stcp_send_file(stcpSock _init_data, char *_file_name);
int32_t stcp_recv_data(stcpSock _init_data, unsigned char* buff, int32_t size_set);

#ifdef __STCP_SSL__
  int32_t stcp_ssl_send_data(stcpSock _init_data, unsigned char* buff, int32_t size_set);
  int8_t stcp_ssl_send_file(stcpSock _init_data, char *_file_name);
  int32_t stcp_ssl_recv_data(stcpSock _init_data, unsigned char* buff, int32_t size_set);
#endif

int8_t stcp_url_parser(char *_url, char *_host, char *_protocol, char *_end_point, uint16_t *_port);
char *stcp_http_content_generator(uint16_t _sizeof_content, char *_content_format, ...);
unsigned char *stcp_http_generate_multipart_header(char *_stcp_multipart_header_input, char *_boundary_output, uint16_t *_length_part);
unsigned char *stcp_http_request(char *_req_type, char *_url, char *_header, char *_content, stcp_request_type _request_type);

void stcp_close(stcpSock *init_data);

#ifdef __STCP_SSL__
  void stcp_ssl_close(stcpSock *init_data);
#endif

/* ADDITIONAL PURPOSE */
#ifdef __STCP_PING__
  struct stcp_ping_summary stcp_ping(char *ADDRESS, uint16_t NUM_OF_PING);
#endif
#endif