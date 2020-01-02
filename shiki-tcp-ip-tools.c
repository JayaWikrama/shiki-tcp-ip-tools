/*
    lib info    : SHIKI_LIB_GROUP - TCP_IP
    ver         : 1.01.19.10.03.18
    author      : Jaya Wikrama, S.T.
    e-mail      : jayawikrama89@gmail.com
    Copyright (c) 2019 HANA,. Jaya Wikrama

    Support     : tcp-ip client/server
                : tcp-ip ssl client
                : http get/post request
                : https get/post request
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <netdb.h> 
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "shiki-tcp-ip-tools.h"

#define MAX_BUFF_LEN 80
#define SIZE_PER_RECV 128
#define SA struct sockaddr

int8_t debug_mode_status = 1;

static void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...);
static int8_t stcp_check_ip(char *_ip_address);
static int16_t stcp_get_content_length(char *_text_source);
static void stcp_select_request(char *_response, char *response, stcp_request_type _request_type);

static void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...){
	if (debug_mode_status == 1){
        time_t debug_time;
	    struct tm *d_tm;
	    va_list aptr;
		
	    time(&debug_time);
	    d_tm = localtime(&debug_time);
	
	    char tmp_debug_msg[100];
	    va_start(aptr, debug_msg);
	    vsprintf(tmp_debug_msg, debug_msg, aptr);
	    va_end(aptr);
	
	    printf("%02d-%02d-%04d %02d:%02d:%02d %s: %s: %s", d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec, debug_type, function_name, tmp_debug_msg);
    }
}

static int8_t stcp_check_ip(char *_ip_address){
    // check length
    if (strlen(_ip_address) > 15){
        return -1;
    }
    // check point and value per point
    int8_t point_counter = 0;
    int8_t aviable_value_per_point[4];
    aviable_value_per_point[0] = 0;
    aviable_value_per_point[1] = 0;
    aviable_value_per_point[2] = 0;
    aviable_value_per_point[3] = 0;
    for (int8_t i=0; i<strlen(_ip_address); i++){
        if(_ip_address[i] == '.'){
            point_counter++;
        }
        else if (point_counter < 4){
            aviable_value_per_point[point_counter]++;
        }
        else {
            return -2;
        }
    }
    if (point_counter != 3){
        return -2;
    }
    if (aviable_value_per_point[0] == 0 ||
     aviable_value_per_point[1] == 0 ||
     aviable_value_per_point[2] == 0 ||
     aviable_value_per_point[3] == 0
    ){
        return -3;
    }
    if (aviable_value_per_point[0] > 3 ||
     aviable_value_per_point[1] > 3 ||
     aviable_value_per_point[2] > 3 ||
     aviable_value_per_point[3] > 3
    ){
        return -3;
    }
    return 0;
}

struct stcp_sock_data stcp_server_init(char *ADDRESS, uint16_t PORT, int8_t infinite_retry_mode, int8_t debug_mode){
    struct stcp_sock_data init_data;
    socklen_t len;
    int8_t retval = 0;
    struct sockaddr_in servaddr, cli;
    do{
        init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
        if (init_data.socket_f == -1) {
            stcp_debug(__func__, "CRITICAL", "socket creation failed...\n");
            retval = init_data.socket_f;
        }
        else{
            stcp_debug(__func__, "INFO", "Socket successfully created : %d\n", init_data.socket_f);
            memset(&servaddr, 0x00, sizeof(servaddr));
            servaddr.sin_family = AF_INET;
            servaddr.sin_port = htons(PORT);
            if(stcp_check_ip(ADDRESS) != 0){
                struct hostent *host;
                host = gethostbyname(ADDRESS);
                if (host != NULL){
                    memcpy(&servaddr.sin_addr.s_addr,host->h_addr,host->h_length);
                }
                else {
                    stcp_debug(__func__, "ERROR", "failed to get host by name", ADDRESS);
                    stcp_close(init_data);
                    return init_data;
                }
            }
            else {
                servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
            }

            if ((bind(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
                stcp_debug(__func__, "CRITICAL", "socket bind failed...\n");
                if (infinite_retry_mode == 1) stcp_debug(__func__, "INFO", "trying to create a socket...\n");;
                retval = -2; 
                close(init_data.socket_f);
                sleep(1);
            }
            else{
                stcp_debug(__func__, "INFO", "Socket successfully binded..\n");

                if ((listen(init_data.socket_f, 5)) != 0) { 
                    stcp_debug(__func__, "CRITICAL", "Listen failed...\n");
                    retval = -3;
                    close(init_data.socket_f);
                }
                else{
                    stcp_debug(__func__, "INFO", "Server listening..\n"); 
                    len = sizeof(cli);

                    init_data.connection_f = accept(init_data.socket_f, (SA*)&cli, &len);

                    if (init_data.connection_f < 0) { 
                        stcp_debug(__func__, "CRITICAL", "server acccept failed...\n"); 
                        retval = -4;
                    }
                    else{
                        stcp_debug(__func__, "INFO", "server acccept the client...\n");
                    }
                }
            }
        }
    } while (retval < 0 && infinite_retry_mode == 1);
    if(debug_mode == STCP_DEBUG_OFF || debug_mode == STCP_DEBUG_ON) debug_mode_status = debug_mode;
    return init_data;
}

struct stcp_sock_data stcp_client_init(char *ADDRESS, uint16_t PORT, int8_t infinite_retry_mode, int8_t debug_mode){
    struct stcp_sock_data init_data;
    int8_t retval = 0;
    struct sockaddr_in servaddr;

    do{
        init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
        if (init_data.socket_f == -1) {
            stcp_debug(__func__, "CRITICAL", "socket creation failed...\n");
            retval = init_data.socket_f;
        }
        else{
            retval = init_data.socket_f;
            stcp_debug(__func__, "INFO", "Socket successfully created : %d\n", init_data.socket_f);
            memset(&servaddr, 0x00, sizeof(servaddr));
            servaddr.sin_family = AF_INET;
            servaddr.sin_port = htons(PORT);
            if(stcp_check_ip(ADDRESS) != 0){
                struct hostent *host;
                host = gethostbyname(ADDRESS);
                if (host != NULL){
                    memcpy(&servaddr.sin_addr.s_addr,host->h_addr,host->h_length);
                }
                else {
                    stcp_debug(__func__, "ERROR", "failed to get host by name", ADDRESS);
                    stcp_close(init_data);
                    return init_data;
                }
            }
            else {
                servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
            }

            stcp_debug(__func__, "INFO", "waiting for server...\n");
            while (connect(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
                sleep(1); 
            }
            init_data.connection_f = init_data.socket_f;
	        stcp_debug(__func__, "INFO", "connected to the server..\n");
        }
    } while (retval < 0 && infinite_retry_mode == 0);
    if(debug_mode == STCP_DEBUG_OFF || debug_mode == STCP_DEBUG_ON) debug_mode_status = debug_mode;
    return init_data;
}

struct stcp_sock_data stcp_ssl_client_init(char *ADDRESS, uint16_t PORT, int8_t infinite_retry_mode, int8_t debug_mode){
    struct stcp_sock_data init_data;
    int8_t retval = 0;
    struct sockaddr_in servaddr;

    do{
        init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
        if (init_data.socket_f == -1) {
            stcp_debug(__func__, "CRITICAL", "socket creation failed...\n");
            retval = init_data.socket_f;
        }
        else{
            retval = init_data.socket_f;
            stcp_debug(__func__, "INFO", "Socket successfully created : %d\n", init_data.socket_f);
            memset(&servaddr, 0x00, sizeof(servaddr));
            servaddr.sin_family = AF_INET;
            servaddr.sin_port = htons(PORT);
            if(stcp_check_ip(ADDRESS) != 0){
                struct hostent *host;
                host = gethostbyname(ADDRESS);
                if (host != NULL){
                    memcpy(&servaddr.sin_addr.s_addr,host->h_addr,host->h_length);
                }
                else {
                    stcp_debug(__func__, "ERROR", "failed to get host by name", ADDRESS);
                    stcp_close(init_data);
                    return init_data;
                }
            }
            else {
                servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
            }

            stcp_debug(__func__, "INFO", "waiting for server...\n");
            while (connect(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
                sleep(1); 
            }
            
            SSL_load_error_strings ();
            if (SSL_library_init () < 0){
                stcp_debug(__func__, "WARNING", "failed when init SSL Library\n");
            }

            SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method ());

            if (ssl_ctx == NULL){
                stcp_debug(__func__, "WARNING", "unable to create new SSL context structure\n");
            }

            init_data.ssl_connection_f = SSL_new(ssl_ctx);
            SSL_set_fd(init_data.ssl_connection_f, init_data.socket_f);

            int8_t err = SSL_connect(init_data.ssl_connection_f);
            if (err != 1){
                stcp_debug(__func__, "WARNING", "ssl connection failed\n");
            }
            init_data.connection_f = init_data.socket_f;
	        stcp_debug(__func__, "INFO", "connected to the server..\n");
            free(ssl_ctx);
        }
    } while (retval < 0 && infinite_retry_mode == 0);
    if(debug_mode == STCP_DEBUG_OFF || debug_mode == STCP_DEBUG_ON) debug_mode_status = debug_mode;
    return init_data;
}

int16_t stcp_send_data(struct stcp_sock_data com_data, char* buff, int16_t size_set){
    int16_t bytes;
    bytes = write(com_data.connection_f, buff, size_set*sizeof(char));
    stcp_debug(__func__, "INFO", "success to send %d data\n", bytes);
    return bytes;
}

int16_t stcp_recv_data(struct stcp_sock_data com_data, char* buff, int16_t size_set){
    int16_t bytes;
    bytes = read(com_data.connection_f, buff, size_set*sizeof(char));
    stcp_debug(__func__, "INFO", "success to receive %d data\n", bytes);
    return bytes;
}

int16_t stcp_ssl_send_data(struct stcp_sock_data com_data, char* buff, int16_t size_set){
    int16_t bytes;
    bytes = SSL_write(com_data.ssl_connection_f, buff, size_set*sizeof(char));
    stcp_debug(__func__, "INFO", "success to send %d data\n", bytes);
    return bytes;
}

int16_t stcp_ssl_recv_data(struct stcp_sock_data com_data, char* buff, int16_t size_set){
    int16_t bytes;
    bytes = SSL_read(com_data.ssl_connection_f, buff, size_set*sizeof(char));
    stcp_debug(__func__, "INFO", "success to receive %d data\n", bytes);
    return bytes;
}

int8_t stcp_http_get(char *_host, uint16_t _port, char *_end_point, char *_header, char *_content, char *_response, stcp_request_type _request_type){
    char message_request[1024];
    char *response = NULL;
    response = (char *) malloc(2 * sizeof(char));
    memset(response, 0x00, 2 * sizeof(char));
    if (response == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate memory\n");
        return -1;
    }
    struct stcp_sock_data socket_f = stcp_client_init(_host, _port, WITHOUT_RETRY, STCP_DEBUG_ON);
    if (_header != NULL && _content != NULL){
        sprintf(message_request,
         "GET /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n"
         "Content-Length: %d\r\n\r\n"
         "%s\r\n\r\n",
         _end_point,
         _host,
         _header,
         (int16_t) strlen(_content),
         _content
        );
    }
    else if (_content == NULL && _header != NULL){
        sprintf(message_request,
         "GET /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n\r\n",
         _end_point,
         _host,
         _header
        );
    }
    else if (_header == NULL){
        sprintf(message_request,
         "GET /%s HTTP/1.1\r\n"
         "Host: %s\r\n\r\n",
         _end_point,
         _host
        );
    }
    stcp_debug(__func__, "INFO", "HTTP Request:\n");
    printf("%s\n", message_request);
    stcp_send_data(socket_f, message_request, strlen(message_request));
    int16_t bytes = 0;
    do {
        char response_tmp[SIZE_PER_RECV + 1];
        memset(response_tmp, 0x00, SIZE_PER_RECV + 1);
        bytes = stcp_recv_data(socket_f, response_tmp, SIZE_PER_RECV);
        if (bytes == -1){
            stcp_debug(__func__, "ERROR", "Lost Connection\n");
            break;
        }
        else if (bytes == 0){
            break;
        }
        response = (char *) realloc(response, bytes + (int) strlen(response));
        strcat(response, response_tmp);
    } while (bytes >= SIZE_PER_RECV);
    stcp_close(socket_f);
    stcp_select_request(_response, response, _request_type);
    free(response);
    return 0;
}

int8_t stcp_http_post(char *_host, uint16_t _port, char *_end_point, char *_header, char *_content, char *_response, stcp_request_type _request_type){
    char message_request[1024];
    char *response = NULL;
    response = (char *) malloc(2 * sizeof(char));
    memset(response, 0x00, 2 * sizeof(char));
    if (response == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate memory\n");
        return -1;
    }
    struct stcp_sock_data socket_f = stcp_client_init(_host, _port, WITHOUT_RETRY, STCP_DEBUG_ON);
    if (_header != NULL && _content != NULL){
        sprintf(message_request,
         "POST /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n"
         "Content-Length: %d\r\n\r\n"
         "%s\r\n\r\n",
         _end_point,
         _host,
         _header,
         (int16_t) strlen(_content),
         _content
        );
    }
    else if (_content == NULL && _header != NULL){
        sprintf(message_request,
         "POST /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n\r\n",
         _end_point,
         _host,
         _header
        );
    }
    else if (_header == NULL){
        sprintf(message_request,
         "POST /%s HTTP/1.1\r\n"
         "Host: %s\r\n\r\n",
         _end_point,
         _host
        );
    }
    stcp_debug(__func__, "INFO", "HTTP Request:\n");
    printf("%s\n", message_request);
    stcp_send_data(socket_f, message_request, strlen(message_request));
    int16_t bytes = 0;
    do {
        char response_tmp[SIZE_PER_RECV + 1];
        memset(response_tmp, 0x00, SIZE_PER_RECV + 1);
        bytes = stcp_recv_data(socket_f, response_tmp, SIZE_PER_RECV);
        if (bytes == -1){
            stcp_debug(__func__, "ERROR", "Lost Connection\n");
            break;
        }
        else if (bytes == 0){
            break;
        }
        response = (char *) realloc(response, bytes + (int) strlen(response));
        strcat(response, response_tmp);
    } while (bytes >= SIZE_PER_RECV);
    stcp_close(socket_f);
    stcp_select_request(_response, response, _request_type);
    free(response);
    return 0;
}

int8_t stcp_https_get(char *_host, uint16_t _port, char *_end_point, char *_header, char *_content, char *_response, stcp_request_type _request_type){
    char message_request[1024];
    char *response = NULL;
    response = (char *) malloc(2 * sizeof(char));
    memset(response, 0x00, 2 * sizeof(char));
    if (response == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate memory\n");
        return -1;
    }
    struct stcp_sock_data socket_f = stcp_ssl_client_init(_host, _port, WITHOUT_RETRY, STCP_DEBUG_ON);
    if (_header != NULL && _content != NULL){
        sprintf(message_request,
         "GET /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n"
         "Content-Length: %d\r\n\r\n"
         "%s\r\n\r\n",
         _end_point,
         _host,
         _header,
         (int16_t) strlen(_content),
         _content
        );
    }
    else if (_content == NULL && _header != NULL){
        sprintf(message_request,
         "GET /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n\r\n",
         _end_point,
         _host,
         _header
        );
    }
    else if (_header == NULL){
        sprintf(message_request,
         "GET /%s HTTP/1.1\r\n"
         "Host: %s\r\n\r\n",
         _end_point,
         _host
        );
    }
    stcp_debug(__func__, "INFO", "HTTP Request:\n");
    printf("%s\n", message_request);
    stcp_ssl_send_data(socket_f, message_request, strlen(message_request));
    int16_t bytes = 0;
    do {
        char response_tmp[SIZE_PER_RECV + 1];
        memset(response_tmp, 0x00, SIZE_PER_RECV + 1);
        bytes = stcp_ssl_recv_data(socket_f, response_tmp, SIZE_PER_RECV);
        if (bytes == -1){
            stcp_debug(__func__, "ERROR", "Lost Connection\n");
            break;
        }
        else if (bytes == 0){
            break;
        }
        response = (char *) realloc(response, bytes + (int) strlen(response));
        strcat(response, response_tmp);
    } while (bytes >= SIZE_PER_RECV);
    stcp_ssl_close(socket_f);
    stcp_select_request(_response, response, _request_type);
    free(response);
    return 0;
}

int8_t stcp_https_post(char *_host, uint16_t _port, char *_end_point, char *_header, char *_content, char *_response, stcp_request_type _request_type){
    char message_request[1024];
    char *response = NULL;
    response = (char *) malloc(2 * sizeof(char));
    memset(response, 0x00, 2 * sizeof(char));
    if (response == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate memory\n");
        return -1;
    }
    struct stcp_sock_data socket_f = stcp_ssl_client_init(_host, _port, WITHOUT_RETRY, STCP_DEBUG_ON);
    if (_header != NULL && _content != NULL){
        sprintf(message_request,
         "POST /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n"
         "Content-Length: %d\r\n\r\n"
         "%s\r\n\r\n",
         _end_point,
         _host,
         _header,
         (int16_t) strlen(_content),
         _content
        );
    }
    else if (_content == NULL && _header != NULL){
        sprintf(message_request,
         "POST /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n\r\n",
         _end_point,
         _host,
         _header
        );
    }
    else if (_header == NULL){
        sprintf(message_request,
         "POST /%s HTTP/1.1\r\n"
         "Host: %s\r\n\r\n",
         _end_point,
         _host
        );
    }
    stcp_debug(__func__, "INFO", "HTTP Request:\n");
    printf("%s\n", message_request);
    stcp_ssl_send_data(socket_f, message_request, strlen(message_request));
    int16_t bytes = 0;
    do {
        char response_tmp[SIZE_PER_RECV + 1];
        memset(response_tmp, 0x00, SIZE_PER_RECV + 1);
        bytes = stcp_ssl_recv_data(socket_f, response_tmp, SIZE_PER_RECV);
        if (bytes == -1){
            stcp_debug(__func__, "ERROR", "Lost Connection\n");
            break;
        }
        else if (bytes == 0){
            break;
        }
        response = (char *) realloc(response, bytes + (int) strlen(response));
        strcat(response, response_tmp);
    } while (bytes >= SIZE_PER_RECV);
    stcp_ssl_close(socket_f);
    stcp_select_request(_response, response, _request_type);
    free(response);
    return 0;
}

void stcp_close(struct stcp_sock_data init_data){
    if(init_data.socket_f == init_data.connection_f){
        close(init_data.socket_f);
        init_data.socket_f = -1;
    }
    else{
        close(init_data.connection_f);
        close(init_data.socket_f);
        init_data.connection_f = -1;
        init_data.socket_f = -1;
    }
}

void stcp_ssl_close(struct stcp_sock_data init_data){
    if(init_data.socket_f == init_data.connection_f){
        SSL_shutdown(init_data.ssl_connection_f);
        close(init_data.socket_f);
        init_data.socket_f = -1;
    }
    else{
        SSL_shutdown(init_data.ssl_connection_f);
        close(init_data.connection_f);
        close(init_data.socket_f);
        init_data.connection_f = -1;
        init_data.socket_f = -1;
    }
}

static int16_t stcp_get_content_length(char *_text_source){
    char buff_info[17];
    char buff_data[7];
    for (int16_t i=0; i<(strlen(_text_source) - strlen("Content-Length: ")); i++){
        memset(buff_info, 0x00, 17*sizeof(char));
        for (int8_t j=0; j<strlen("Content-Length: "); j++){
            buff_info[j] = _text_source[i + j];
        }
        if (strcmp(buff_info, "Content-Length: ") == 0){
            i = i + strlen("Content-Length: ");
            memset(buff_data, 0x00, 7*sizeof(char));
            for (int8_t j=0; j<6; j++){
                if (j>0 && (_text_source[i + j] < '0' || _text_source[i + j] > '9')){
                    return atoi(buff_data);
                }
                else if (_text_source[i + j] >= '0' && _text_source[i + j] <= '9'){
                    buff_data[j] = _text_source[i + j];
                }
            }
        }
    }
    return 0;
}

static void stcp_select_request(char *_response, char *response, stcp_request_type _request_type){
    if (_request_type == STCP_REQ_COMPLETE){
        strcpy(_response, response);
    }
    else if (_request_type == STCP_REQ_HEADER_ONLY){
        int16_t content_length = stcp_get_content_length(response);
        char response_tmp[(strlen(response) - content_length) - 1];
        if (content_length == 0){
            strcpy(_response, response);
        } else {
            memset(response_tmp, 0x00, ((strlen(response) - content_length) - 1)*sizeof(char));
            for (int16_t i=0; i<(strlen(response) - content_length - 3); i++){
                response_tmp[i] = response[i];
            }
            strcpy(_response, response_tmp);
        }
    }
    else if (_request_type == STCP_REQ_CONTENT_ONLY){
        int16_t content_length = stcp_get_content_length(response);
        char response_tmp[content_length + 1];
        if (content_length == 0){
            strcpy(_response, response);
        } else {
            memset(response_tmp, 0x00, (content_length + 1)*sizeof(char));
            for (int16_t i=0; i<content_length; i++){
                response_tmp[i] = response[i + (strlen(response) - content_length)];
            }
            strcpy(_response, response_tmp);
        }
    }
}