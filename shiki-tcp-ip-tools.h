#ifndef __SHIKI_TCP_IP_TOOLS__
#define __SHIKI_TCP_IP_TOOLS__

#ifdef __cplusplus
  extern "C" {
#endif

#define __STCP_PING__
#define __STCP_SSL__
#define __STCP_WEBSERVER__
//#define __STCP_DONT_USE_CLIENT__ //uncomment this for use as server only

#include <stdint.h>
#ifdef __STCP_SSL__
  #include <openssl/ssl.h>
  #ifndef X509_FILETYPE_PEM
    #define X509_FILETYPE_PEM 1
  #endif
  #ifndef SSL_FILETYPE_PEM
    #define SSL_FILETYPE_PEM X509_FILETYPE_PEM
  #endif
  typedef enum {
    STCP_SSL_CERT_TYPE_FILE = 0x00, /*!< type of SSL/TLS certificate input is file */
    STCP_SSL_CERT_TYPE_TEXT = 0x01, /*!< type of SSL/TLS certificate input is text that stored in buffer memmory */
    STCP_SSL_KEY_TYPE_FILE = 0x02, /*!< type of SSL/TLS key input is file */
    STCP_SSL_KEY_TYPE_TEXT = 0x03, /*!< type of SSL/TLS key input is text that stored in buffer memmory */
    STCP_SSL_CACERT_TYPE_FILE = 0x04, /*!< type of SSL/TLS cacert input is file */
    STCP_SSL_CACERT_TYPE_TEXT = 0x05 /*!< type of SSL/TLS cacert input is text that stored in buffer memmory */
  } stcp_ssl_certkey_type;
#endif

#if defined __STCP_WEBSERVER__ || defined __STCP_SSL__
  #include "../shiki-linked-list/shiki-linked-list.h"
  typedef SHLink stcpWList;
#endif

typedef enum {
  STCP_DEBUG_OFF = 0x00, /*!< flag to disable stcp_debug */
  STCP_DEBUG_ON = 0x01, /*!< flag to enable stcp_debug */
  WITHOUT_RETRY = 0x02, /*!< flag to enable retry routine in server/client initialize */
  INFINITE_RETRY = 0x03, /*!< flag to disable retry routine in server/client initialize */
} stcp_global_def;

typedef enum {
  STCP_DEBUG_INFO = 0x00, /*!< flag to output debug in stcp_debug as INFO */
  STCP_DEBUG_DOWNLOAD = 0x01, /*!< flag to output debug in stcp_debug as DOWNLOAD */
  STCP_DEBUG_VERSION = 0x02, /*!< flag to output debug in stcp_debug as VERSION */
  STCP_DEBUG_WEBSERVER = 0x03, /*!< flag to output debug in stcp_debug as WEBSERVER */
  STCP_DEBUG_WARNING = 0x04, /*!< flag to output debug in stcp_debug as WARNING */
  STCP_DEBUG_ERROR = 0x05, /*!< flag to output debug in stcp_debug as ERROR */
  STCP_DEBUG_CRITICAL = 0x06 /*!< flag to output debug in stcp_debug as CRITICAL */
} stcp_debug_type;

#define STCP_MAX_LENGTH_FILE_NAME 16

struct stcp_sock_data{
  int socket_f; /*!< variable to store socket descriptor */
  int connection_f; /*!< variable to store accepted client socket */
  #ifdef __STCP_SSL__
    SSL *ssl_connection_f; /*!< variable to store SSL/TLS connection informations */
  #endif
};

typedef struct stcp_sock_data stcpSock;

typedef struct stcp_subhead_var{
  uint16_t stcp_sub_pos; /*!< start position of data */
  uint16_t stcp_sub_size; /*!< size of data */
} stcpSHead; /*!< structure of segmentation data */

#ifdef __STCP_PING__
  struct stcp_ping_summary{
    int8_t state; /*!< flag to determine state of PING process (0 if all process is run correctly) */
    uint16_t tx_counter; /*!< number of packet transmit */
    uint16_t rx_counter; /*!< number of packet received */
    uint16_t max_rtt; /*!< maximum tarnsfer time */
    uint16_t min_rtt; /*!< minimum transfer time */
    uint16_t avg_rtt; /*!< transfer time average */
    uint8_t packet_loss; /*!< number of packet lose */
    uint32_t time_counter; /*!< time of PING process */
  }; /*!< PING data statistics */
#endif

#ifdef __STCP_WEBSERVER__
  typedef enum{
    STCP_401_UNAUTHOIZED = 0x01, /*!< flag response code if request is unauthorized */
    STCP_404_NOT_FOUND = 0x02, /*!< flag response code if request not found*/
    STCP_405_METHOD_NOT_ALLOWED = 0x03 /*!< flag response code if request not allowed */
  } stcp_webserver_negative_code;

  #ifdef __STCP_SSL__
  typedef enum{
    STCP_SSL_WEBSERVER_WITHOUT_VERIFY_CLIENT = 0x00, /*!< without client certificate verification */
    STCP_SSL_WEBSERVER_VERIFY_REMOTE_CLIENT = 0x01 /*!< force client certificate verification */
  } stcp_ssl_webserver_verify_mode; /*!< SSL Verify Mode on STCP Webserver routine */
  #endif

  struct stcp_webserver_info{
    char *server_header; /*!< HTTP server header that will be send to client */
    unsigned char *rcv_header; /*!< HTTP client header that has been received */
    stcpSHead request; /*!< segment of request type (GET/POST/PATCH/etc) */
    stcpSHead data_end_point; /*!< segment of endpoint data */
    stcpSHead rcv_endpoint; /*!< segment of request endpoint */
    stcpSHead rcv_boundary; /*!< segment of multipart-form data boundary */
    stcpSHead rcv_content_type; /*!< segment of content-type */
    stcpSHead rcv_acception_type;/*!< segment of Accept field */
    stcpSHead rcv_auth; /*!< segment of auth token */
    stcpSHead rcv_cookies; /*!< segment of cookies */
    stcpSHead rcv_connection_type; /*!< segment of Connection field */
    unsigned char *rcv_content; /*!< HTTP Client content/body that has been received */
    char *ipaddr; /*!< clien ip address */
    uint32_t content_length; /*!< size/length of received HTTP Client content/body */
    uint64_t partial_length; /*!< size/length of received HTTP Client partial-content */
    int8_t comm_protocol; /*!< flag of communication protocol (http/https) */
  }; /*!< Webserver transaction data */

  struct stcp_webserver_header{
    char *content_type; /*!< default value of content-type field on HTTP Server */
    char *accept_type; /*!< default value of Accept field on HTTP Server */
  }; /*!< Webserver default informations */

  typedef struct stcp_webserver_info stcpWInfo;
  typedef struct stcp_webserver_header stcpWHead;
#endif

typedef enum {
  STCP_REQ_COMPLETE = 0, /*!< flag to tell __stcp_http_request__ function to return all HTTP Response data (header + content/body) */
  STCP_REQ_HEADER_ONLY = 1, /*!< flag to tell __stcp_http_request__ function to return HTTP Response header only */
  STCP_REQ_CONTENT_ONLY = 2, /*!< flag to tell __stcp_http_request__ function to return HTTP Response content/body only */
  STCP_REQ_HTTP_STATUS_ONLY = 3, /*!< flag to tell __stcp_http_request__ function to return HTTP Response status code only */
  STCP_REQ_DOWNLOAD_CONTENT = 4, /*!< flag to tell __stcp_http_request__ function to store HTTP Response header content/body to file */
  STCP_REQ_UPLOAD_FILE = 5 /*!< flag to tell __stcp_http_request__ function to send file */
} stcp_request_type; /*!< STCP HTTP Client request type */

typedef enum{
  STCP_SET_TIMEOUT_IN_SEC = 0, /*!< parameter to tell __stcp_setup__ function to set timeout in seconds */
  STCP_SET_TIMEOUT_IN_MILLISEC = 1, /*!< parameter to tell __stcp_setup__ function to set timeout in millseconds */
  STCP_SET_DEBUG_MODE = 2, /*!< parameter to tell __stcp_setup__ function to set debug mode (enable/disable) */
  STCP_SET_SIZE_PER_RECV = 3, /*!< parameter to tell __stcp_setup__ function to set maximum received size for a single received process */
  STCP_SET_SIZE_PER_SEND = 4, /*!< parameter to tell __stcp_setup__ function to set maximum send size for a single send process */
  STCP_SET_INFINITE_MODE_RETRY = 5 /*!< parameter to tell __stcp_setup__ function to set retry mode on Server/Client initialization (enable/disable) */
} stcp_setup_parameter; /*!< STCP common setup parameters */

#ifdef __STCP_WEBSERVER__
typedef enum{
  STCP_SET_KEEP_ALIVE_TIMEOUT_IN_SEC = 6, /*!< parameter to tell __stcp_webserver_setup__ function to set maximum keep-alive connection in seconds */
  STCP_SET_KEEP_ALIVE_TIMEOUT_IN_MILLISEC = 7, /*!< parameter to tell __stcp_webserver_setup__ function to set maximum keep-alive connection in milliseconds */
  STCP_SET_MAX_ELAPSED_CONNECTION = 80, /*!< parameter to tell __stcp_webserver_setup__ function to set maximum elapsed connection in seconds */
  STCP_SET_SLOW_HTTP_ATTACK_BLOCKING_TIME = 81, /*!< parameter to tell __stcp_webserver_setup__ function to set maximum blocking time in seconds for abnormal client */
  STCP_SET_SLOW_HTTP_ATTACK_COUNTER_ACCEPTED = 82, /*!< parameter to tell __stcp_webserver_setup__ function to set maximum counter to determine that the client is abnormal client */
  STCP_SET_MAX_RECEIVED_HEADER = 83, /*!< parameter to tell __stcp_webserver_setup__ function to set maximum header size request accepted */
  STCP_SET_MAX_RECEIVED_DATA = 84 /*!< parameter to tell __stcp_webserver_setup__ function to set maximum data size request accepted */
  #ifdef __STCP_SSL__
  ,
  STCP_SET_WEBSERVER_VERIFY_CERT_MODE = 99 /*!< parameter to tell __stcp_webserver_setup__ function to enable/disable certificate verify mode on HTTPS */
  #endif
} stcp_webserver_setup_parameter; /*!< STCP Webserver setup parameters */
#endif

void stcp_debug(const char *_function_name, stcp_debug_type _debug_type, const char *_debug_msg, ...);

void stcp_view_version();
long stcp_get_version(char *_version);
int8_t stcp_setup(stcp_setup_parameter _setup_parameter, uint32_t _value);
#ifdef __STCP_WEBSERVER__
int8_t stcp_webserver_setup(stcp_webserver_setup_parameter _setup_parameter, uint32_t _value);
#endif
void stcp_lock_setup();
void stcp_unlock_setup();

#ifdef __STCP_SSL__
int8_t stcp_ssl_add_certkey(stcp_ssl_certkey_type _type, const char *_host, const char *_certkey);
int8_t stcp_ssl_remove_certkey(stcp_ssl_certkey_type _type, const char *_host, const char *_certkey);
unsigned char *stcp_ssl_get_cert(const char *_host, stcp_ssl_certkey_type *_type);
unsigned char *stcp_ssl_get_key(const char *_host, stcp_ssl_certkey_type *_type);
unsigned char *stcp_ssl_get_cacert(const char *_host, stcp_ssl_certkey_type *_type);
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
stcpSock stcp_client_init(const char *ADDRESS, uint16_t PORT);
stcpSock stcp_server_init(const char *ADDRESS, uint16_t PORT);

#ifdef __STCP_WEBSERVER__
int8_t stcp_http_webserver_init(
 stcpWInfo *_stcpWI,
 stcpWHead *_stcpWH,
 stcpWList *_stcpWList
);
int8_t stcp_http_webserver_add_negative_code_response(
 stcpWList *_stcpWList,
 stcp_webserver_negative_code _code_param,
 const char *_response_content
);
int8_t stcp_http_webserver_add_response(
 stcpWList *_stcpWList,
 const char *_end_point,
 const char *_response_content,
 const char *_request_method
);
int8_t stcp_http_webserver_add_response_file(
 stcpWList *_stcpWList,
 const char *_end_point,
 const char *_response_file,
 const char *_request_method
);
int8_t stcp_http_webserver_add_response_directory(
 stcpWList *_stcpWList,
 const char *_base_end_point,
 const char *_response_directory,
 const char *_request_method
);
int8_t stcp_http_webserver_add_response_callback(
 stcpWList *_stcpWList,
 const char *_end_point,
 const void *_response_function,
 const char *_request_method
);
int8_t stcp_http_webserver_add_tcp_response_callback(
 stcpWList *_stcpWList,
 const unsigned char *_start_bits,
 uint16_t _start_bits_size,
 const void *_response_function
);
int8_t stcp_http_webserver_set_content_type(
 stcpWHead *_stcpWH,
 const char *_content_type
);
int8_t stcp_http_webserver_set_accept(
 stcpWHead *_stcpWH,
 const char *_accept
);
int8_t stcp_http_webserver(
 const char *ADDRESS,
 uint16_t PORT,
 uint16_t MAX_CLIENT,
 stcpWInfo *_stcpWI,
 stcpWHead *_stcpWH,
 stcpWList _stcpWList
);

int8_t stcp_http_webserver_generate_header(
 stcpWInfo *_stcpWI,
 const char *_response_header,
 const char *_content_type,
 const char *_acception_type,
 uint64_t _content_length
);
char *stcp_http_webserver_generate_full_response(
 stcpWInfo *_stcpWI,
 const char *_response_header,
 const char *_content_type,
 const char *_acception_type,
 char *_content_with_malloc /* memory allocation will be free by function */
);
int8_t stcp_http_webserver_send_file(
 stcpSock _init_data,
 stcpWInfo *_stcpWI,
 stcpWHead *_stcpWH,
 const char *_response_code,
 const char *_file_name
);
void stcp_http_webserver_stop();
#endif

#ifdef __STCP_SSL__
  stcpSock stcp_ssl_client_init(
   const char *ADDRESS,
   uint16_t PORT
  );
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
int32_t stcp_send_data(
 stcpSock _init_data,
 const unsigned char* buff,
 int32_t size_set
);
int8_t stcp_send_file(
 stcpSock _init_data,
 const char *_file_name
);
int32_t stcp_recv_data(
 stcpSock _init_data,
 unsigned char* buff,
 int32_t size_set
);

#ifdef __STCP_SSL__
  int32_t stcp_ssl_send_data(stcpSock _init_data,
   const unsigned char* buff,
   int32_t
   size_set
  );
  int8_t stcp_ssl_send_file(
   stcpSock _init_data,
   const char *_file_name
  );
  int32_t stcp_ssl_recv_data(
   stcpSock _init_data,
   unsigned char* buff,
   int32_t size_set
  );
#endif

int8_t stcp_url_parser(
 const char *_url,
 int8_t *_protocol,
 stcpSHead *_host,
 stcpSHead *_end_point,
 uint16_t *_port
);
char *stcp_http_content_generator(
 unsigned short _size_per_allocate,
 const char *_str_format,
 ...
);
char *stcp_http_str_append(
 char *_buff_source,
 unsigned short _size_per_allocate,
 unsigned short _append_size,
 const char *_str_format, ...
);
unsigned char *stcp_http_generate_multipart_header(
 const char *_stcp_multipart_header_input,
 char *_boundary_output,
 uint16_t *_length_part
);
unsigned char *stcp_http_request(
 const char *_req_type,
 const char *_url,
 const char *_header,
 const char *_content,
 stcp_request_type _request_type
);

void stcp_close(stcpSock *init_data);

#ifdef __STCP_SSL__
  void stcp_ssl_close(stcpSock *init_data);
#endif

/* ADDITIONAL PURPOSE */
#ifdef __STCP_PING__
  struct stcp_ping_summary stcp_ping(
   const char *ADDRESS,
   uint16_t NUM_OF_PING
  );
#endif

#ifdef __cplusplus
  }
#endif

#endif