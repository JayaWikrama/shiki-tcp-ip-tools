/*
    lib info    : SHIKI_LIB_GROUP - TCP_IP
    ver         : 2.01.20.02.01
    author      : Jaya Wikrama, S.T.
    e-mail      : jayawikrama89@gmail.com
    Copyright (c) 2019 HANA,. Jaya Wikrama

    Support     : tcp-ip client/server
                : tcp-ip ssl client
                : http request
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <netdb.h> 
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef __linux__
    #include <arpa/inet.h>
#endif
#include "shiki-tcp-ip-tools.h"

#define SA struct sockaddr

uint16_t SIZE_PER_RECV = 128;

int8_t debug_mode_status = STCP_DEBUG_OFF;
int8_t infinite_retry_mode = WITHOUT_RETRY;
uint16_t time_out_in_seconds = 0;

static void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...);
static int8_t stcp_check_ip(char *_ip_address);
static int16_t stcp_get_content_length(char *_text_source);
static char *stcp_select_request(char *response, stcp_request_type _request_type);

static void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...){
	if (debug_mode_status == 1){
        time_t debug_time;
	    struct tm *d_tm;
	    va_list aptr;
		
	    time(&debug_time);
	    d_tm = localtime(&debug_time);
	
	    char* tmp_debug_msg;
        tmp_debug_msg = (char *) malloc(256*sizeof(char));
        if (tmp_debug_msg == NULL){
            printf("%02d-%02d-%04d %02d:%02d:%02d ERROR: %s: failed to allocate debug variable memory",
             d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec, __func__
            );
            return;
        }
	    va_start(aptr, debug_msg);
	    vsprintf(tmp_debug_msg, debug_msg, aptr);
	    va_end(aptr);
	    printf("%02d-%02d-%04d %02d:%02d:%02d %s: %s: %s", d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec, debug_type, function_name, tmp_debug_msg);
        free(tmp_debug_msg);
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

int8_t stcp_setup(stcp_setup_parameter _setup_parameter, int16_t _value){
    if (_setup_parameter == STCP_SET_TIMEOUT){
        time_out_in_seconds = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_DEBUG_MODE){
        if ((int8_t)_value == STCP_DEBUG_ON || (int8_t)_value == STCP_DEBUG_OFF){
            debug_mode_status = (int8_t)_value;
        }
        else {
            stcp_debug(__func__, "WARNING", "wrong value\n");
        }
    }
    else if(_setup_parameter == STCP_SET_SIZE_PER_RECV){
        SIZE_PER_RECV = (uint16_t) _value;
    }
    else if (_setup_parameter == STCP_SET_INFINITE_MODE_RETRY){
        if ((int8_t)_value == INFINITE_RETRY || (int8_t)_value == WITHOUT_RETRY){
            infinite_retry_mode = (int8_t)_value;
        }
        else {
            stcp_debug(__func__, "WARNING", "wrong value\n");
        }
    }
    else {
        stcp_debug(__func__, "WARNING", "wrong parameters\n");
    }
    return 0;
}

struct stcp_sock_data stcp_server_init(char *ADDRESS, uint16_t PORT){
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
                    servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
                }
                else {
                    stcp_debug(__func__, "ERROR", "failed to get host by name\n", ADDRESS);
                    stcp_close(&init_data);
                    return init_data;
                }
            }
            else {
                servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
            }

            if (time_out_in_seconds > 0){
                struct timeval tv;
                tv.tv_sec = time_out_in_seconds;
                tv.tv_usec = 0;
                setsockopt(init_data.socket_f, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
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
    } while (retval < 0 && infinite_retry_mode == INFINITE_RETRY);
    return init_data;
}

struct stcp_sock_data stcp_client_init(char *ADDRESS, uint16_t PORT){
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
                    servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
                }
                else {
                    stcp_debug(__func__, "ERROR", "failed to get host by name\n", ADDRESS);
                    stcp_close(&init_data);
                    return init_data;
                }
            }
            else {
                servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
            }

            if (time_out_in_seconds > 0){
                struct timeval tv;
                tv.tv_sec = time_out_in_seconds;
                tv.tv_usec = 0;
                setsockopt(init_data.socket_f, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
            }

            stcp_debug(__func__, "INFO", "waiting for server...\n");
            if (time_out_in_seconds > 0){
                uint16_t time_out_connect = 2;
                int8_t retval = 0;
                while ((retval = connect(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr))) != 0 && time_out_connect > 0) {
                    usleep(1000);
                    time_out_connect--;
                    stcp_debug(__func__, "INFO", "timeout counter: %i\n", time_out_connect);
                }
                if (retval != 0){
                    stcp_debug(__func__, "WARNING", "waiting for server timeout\n");
                    stcp_close(&init_data);
                    return init_data;
                }
            }
            else {
                while (connect(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr)) != 0) {
                    sleep(1); 
                }
            }
            init_data.connection_f = init_data.socket_f;
	        stcp_debug(__func__, "INFO", "connected to the server..\n");
        }
    } while (retval < 0 && infinite_retry_mode == INFINITE_RETRY);
    return init_data;
}


struct stcp_sock_data stcp_ssl_client_init(char *ADDRESS, uint16_t PORT){
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
                    servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
                }
                else {
                    stcp_debug(__func__, "ERROR", "failed to get host by name\n", ADDRESS);
                    stcp_close(&init_data);
                    return init_data;
                }
            }
            else {
                servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
            }

            if (time_out_in_seconds > 0){
                struct timeval tv;
                tv.tv_sec = time_out_in_seconds;
                tv.tv_usec = 0;
                setsockopt(init_data.socket_f, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
            }

            stcp_debug(__func__, "INFO", "waiting for server...\n");
            if (time_out_in_seconds > 0){
                uint16_t time_out_connect = 2;
                int8_t retval = 0;
                while ((retval = connect(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr))) != 0 && time_out_connect > 0) {
                    usleep(1000);
                    time_out_connect--;
                    stcp_debug(__func__, "INFO", "timeout counter: %i\n", time_out_connect);
                }
                if (retval != 0){
                    stcp_debug(__func__, "WARNING", "waiting for server timeout\n");
                    stcp_close(&init_data);
                    return init_data;
                }
            }
            else {
                while (connect(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr)) != 0) {
                    sleep(1); 
                }
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
            SSL_CTX_free(ssl_ctx);
        }
    } while (retval < 0 && infinite_retry_mode == INFINITE_RETRY);
    return init_data;
}


int16_t stcp_send_data(struct stcp_sock_data com_data, char* buff, int16_t size_set){
    int16_t bytes;
    bytes = write(com_data.connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to send %d data\n", bytes);
    else if (time_out_in_seconds > 0){
        stcp_debug(__func__, "WARNING", "send %d data. request timeout\n", bytes);
    }
    return bytes;
}

int16_t stcp_recv_data(struct stcp_sock_data com_data, char* buff, int16_t size_set){
    int16_t bytes;
    bytes = read(com_data.connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to receive %d data\n", bytes);
    else if (time_out_in_seconds > 0){
        stcp_debug(__func__, "WARNING", "send %d data. request timeout\n", bytes);
    }
    return bytes;
}


int16_t stcp_ssl_send_data(struct stcp_sock_data com_data, char* buff, int16_t size_set){
    int16_t bytes;
    bytes = SSL_write(com_data.ssl_connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to send %d data\n", bytes);
    else if (time_out_in_seconds > 0){
        stcp_debug(__func__, "WARNING", "send %d data. request timeout\n", bytes);
    }
    return bytes;
}

int16_t stcp_ssl_recv_data(struct stcp_sock_data com_data, char* buff, int16_t size_set){
    int16_t bytes;
    bytes = SSL_read(com_data.ssl_connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to receive %d data\n", bytes);
    else if (time_out_in_seconds > 0){
        stcp_debug(__func__, "WARNING", "send %d data. request timeout\n", bytes);
    }
    return bytes;
}


int8_t stcp_url_parser(char *_url, char *_host, char *_protocol, char *_end_point, uint16_t *_port){
    if (strncmp(_url, "http://", 7) == 0 || strncmp(_url, "https://", 8) == 0){
        char *host;
        char *end_point;
        char *buff;
        host = (char *) malloc(2*sizeof(char));
        if (host == NULL){
            stcp_debug(__func__, "ERROR", "failed to allocate host valriable memory\n");
            return -1;
        }
        end_point = (char *) malloc(2*sizeof(char));
        if (end_point == NULL){
            free(host);
            stcp_debug(__func__, "ERROR", "failed to allocate end_point valriable memory\n");
            return -1;
        }
        buff = (char *) malloc(9*sizeof(char));
        if (buff == NULL){
            free(host);
            free(end_point);
            stcp_debug(__func__, "ERROR", "failed to allocate buff valriable memory\n");
            return -1;
        }
        uint16_t idx_char_url = 0;
        uint8_t idx_char_buff = 0;
        memset(buff, 0x00, 9*sizeof(char));
        strcpy(_end_point, "");
        memset(end_point, 0x00, 2*sizeof(char));
        if (strncmp(_url, "http://", 7) == 0){
            strcpy(_protocol, "http");
            *_port = 80;
            idx_char_url = 7;
        }
        else {
            strcpy(_protocol, "https");
            *_port = 443;
            idx_char_url = 8;
        }
        while(_url[idx_char_url] != '/' && _url[idx_char_url] != ':' && _url[idx_char_url] != 0x00){
            host = (char *) realloc(host, (idx_char_buff + 2)*sizeof(char));
            host[idx_char_buff] = _url[idx_char_url];
            host[idx_char_buff + 1] = 0x00;
            idx_char_url++;
            idx_char_buff++;
        }
        strcpy(_host, host);
        free(host);
        if (_url[idx_char_url] == 0x00){
            free(end_point);
            free(buff);
            return 1;
        }
        idx_char_url++;
        idx_char_buff = 0;
        if (_url[idx_char_url - 1] == ':'){
            while(_url[idx_char_url] != '/' && _url[idx_char_url] != 0x00){
                buff[idx_char_buff] = _url[idx_char_url];
                idx_char_url++;
                idx_char_buff++;
            }
            *_port = (uint16_t) atoi(buff);
            idx_char_url++;
        }
        memset(buff, 0x00, 9*sizeof(char));
        if (_url[idx_char_url - 1] == 0x00){
            free(end_point);
            free(buff);
            return 1;
        }
        idx_char_buff = 0;
        while(_url[idx_char_url] != 0x00){
            end_point = (char *) realloc(end_point, (idx_char_buff + 2)*sizeof(char));
            end_point[idx_char_buff] = _url[idx_char_url];
            end_point[idx_char_buff + 1] = 0x00;
            idx_char_url++;
            idx_char_buff++;
        }
        if (strlen(end_point) > 0){
            strcpy(_end_point, end_point);
        }
        free(end_point);
        free(buff);
    }
    else {
        stcp_debug(__func__, "ERROR", "undefined protocol (http/https - select one)\n");
        return -1;
    }
    return 0;
}

char *stcp_http_request(char *_req_type, char *_url, char *_header, char *_content, stcp_request_type _request_type){
    char *message_request;
    char *host;
    char *end_point;
    char *response;
    char *protocol;
    uint16_t length_of_message = 0;
    uint16_t port = 0;
    length_of_message = strlen(_req_type) + strlen(
     " / HTTP/1.1\r\n"
     "Host: \r\n"
     "\r\n"
     "Content-Length: 00000\r\n\r\n"
     "\r\n\r\n");
    message_request = (char *) malloc((length_of_message + 1) * sizeof(char));
    if (message_request == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate message variable memory\n");
        return NULL;
    }
    host = (char *) malloc(strlen(_url) * sizeof(char));
    if (host == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate host variable memory\n");
        free(message_request);
        return NULL;
    }
    end_point = (char *) malloc(strlen(_url) * sizeof(char));
    if (end_point == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate end_point variable memory\n");
        free(message_request);
        free(host);
        return NULL;
    }
    protocol = (char *) malloc(6 * sizeof(char));
    if (protocol == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate protocol variable memory\n");
        free(message_request);
        free(host);
        free(end_point);
        return NULL;
    }
    response = (char *) malloc(2 * sizeof(char));
    if (response == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate response variable memory\n");
        free(message_request);
        free(host);
        free(end_point);
        free(protocol);
        return NULL;
    }
    int8_t retval = stcp_url_parser(_url, host, protocol, end_point, &port);
    if (retval == -1){
        free(message_request);
        free(host);
        free(end_point);
        free(protocol);
        free(response);
        return NULL;
    }
    stcp_debug(__func__, "INFO", "protocol: %s\n", protocol);
    stcp_debug(__func__, "INFO", "host: %s\n", host);
    stcp_debug(__func__, "INFO", "end point: %s\n", end_point);
    stcp_debug(__func__, "INFO", "port: %d\n", port);
    uint16_t length_tmp = 0;
    length_tmp = strlen(host);
    length_of_message = length_of_message + length_tmp;
    host = (char *) realloc(host, (length_tmp + 1)*sizeof(char));
    length_tmp = strlen(end_point);
    length_of_message = length_of_message + length_tmp;
    end_point = (char *) realloc(end_point, (length_tmp + 1)*sizeof(char));
    
    struct stcp_sock_data socket_f;
    if (strcmp(protocol, "http")==0){
        socket_f = stcp_client_init(host, port);
    }
    else {
        socket_f = stcp_ssl_client_init(host, port);
    }
    if (socket_f.socket_f <= 0){
        free(message_request);
        free(host);
        free(end_point);
        free(protocol);
        response = (char *) realloc(response, 17*sizeof(char));
        strcpy(response, "no route to host");
        return response;
    }

    if (_header != NULL && _content != NULL){
        length_of_message = length_of_message + strlen(_header) + strlen(_content);
        message_request = (char *) realloc(message_request, (length_of_message + 1)*sizeof(char));
        memset(message_request, 0x00, (length_of_message + 1)*sizeof(char));
        sprintf(message_request,
         "%s /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n"
         "Content-Length: %d\r\n\r\n"
         "%s\r\n\r\n",
         _req_type,
         end_point,
         host,
         _header,
         (int16_t) strlen(_content),
         _content
        );
    }
    else if (_content == NULL && _header != NULL){
        length_of_message = length_of_message + strlen(_header);
        message_request = (char *) realloc(message_request, (length_of_message + 1)*sizeof(char));
        memset(message_request, 0x00, (length_of_message + 1)*sizeof(char));
        sprintf(message_request,
         "%s /%s HTTP/1.1\r\n"
         "Host: %s\r\n"
         "%s\r\n\r\n",
         _req_type,
         end_point,
         host,
         _header
        );
    }
    else if (_header == NULL){
        message_request = (char *) realloc(message_request, (length_of_message + 1)*sizeof(char));
        memset(message_request, 0x00, (length_of_message + 1)*sizeof(char));
        sprintf(message_request,
         "%s /%s HTTP/1.1\r\n"
         "Host: %s\r\n\r\n",
         _req_type,
         end_point,
         host
        );
    }
    stcp_debug(__func__, "INFO", "HTTP Request:\n");
    if (debug_mode_status == STCP_DEBUG_ON){
        printf("%s\n", message_request);
    }
    if (strcmp(protocol, "http") == 0){
        stcp_send_data(socket_f, message_request, strlen(message_request));
    }
    else {
        stcp_ssl_send_data(socket_f, message_request, strlen(message_request));
    }
    free(message_request);
    free(host);
    free(end_point);

    int16_t bytes = 0;
    int16_t total_bytes = 0;
    memset(response, 0x00, 2 * sizeof(char));
    do {
        char response_tmp[SIZE_PER_RECV + 1];
        memset(response_tmp, 0x00, SIZE_PER_RECV + 1);
        if (strcmp(protocol, "http") == 0){
            bytes = stcp_recv_data(socket_f, response_tmp, SIZE_PER_RECV);
        }
        else {
            bytes = stcp_ssl_recv_data(socket_f, response_tmp, SIZE_PER_RECV);
        }
        if (bytes == -1){
            stcp_debug(__func__, "ERROR", "Lost Connection\n");
            break;
        }
        else if (bytes == 0){
            break;
        }
        total_bytes = total_bytes + bytes;
        response = (char *) realloc(response, total_bytes + 1);
        memcpy(response + (total_bytes - bytes), response_tmp, bytes);
        response[total_bytes] = 0x00;
    } while (bytes >= SIZE_PER_RECV);
    if (strcmp(protocol, "http") == 0){
        stcp_close(&socket_f);
    }
    else {
        stcp_ssl_close(&socket_f);
    }
    free(protocol);
    if (strlen(response) == 0){
        if (time_out_in_seconds == 0){
            response = (char *) realloc(response, 30*sizeof(char));
            strcpy(response, "bad connection or bad request");
            return response;
        }
        else {
            response = (char *) realloc(response, 16*sizeof(char));
            strcpy(response, "request timeout");
            return response;
        }
    }
    return stcp_select_request(response, _request_type);
}

void stcp_close(struct stcp_sock_data *init_data){
    if(init_data->socket_f == init_data->connection_f){
        close(init_data->socket_f);
        init_data->socket_f = -1;
    }
    else{
        close(init_data->connection_f);
        close(init_data->socket_f);
        init_data->connection_f = -1;
        init_data->socket_f = -1;
    }
}

void stcp_ssl_close(struct stcp_sock_data *init_data){
    if (init_data->socket_f > 0){
        if(init_data->socket_f == init_data->connection_f){
            SSL_shutdown(init_data->ssl_connection_f);
            SSL_free(init_data->ssl_connection_f);
            init_data->ssl_connection_f = NULL;
            close(init_data->socket_f);
            init_data->socket_f = -1;
        }
        else{
            SSL_shutdown(init_data->ssl_connection_f);
            SSL_free(init_data->ssl_connection_f);
            init_data->ssl_connection_f = NULL;
            close(init_data->connection_f);
            close(init_data->socket_f);
            init_data->connection_f = -1;
            init_data->socket_f = -1;
        }
    }
    else {
        if(init_data->socket_f == init_data->connection_f){
            SSL_free(init_data->ssl_connection_f);
            init_data->ssl_connection_f = NULL;
            close(init_data->socket_f);
            init_data->socket_f = -1;
        }
        else{
            SSL_free(init_data->ssl_connection_f);
            init_data->ssl_connection_f = NULL;
            close(init_data->connection_f);
            close(init_data->socket_f);
            init_data->connection_f = -1;
            init_data->socket_f = -1;
        }
    }
}

static int16_t stcp_get_content_length(char *_text_source){
    char *buff_info;
    do {
        buff_info = (char *) malloc(17*sizeof(char));
        if (buff_info == NULL){
            stcp_debug(__func__, "WARNING", "failed to allocate memory\n");
            usleep(1000);
        }
    } while (buff_info == NULL);
    char buff_data[7];
    int16_t i=0;
    for (i=0; i<(strlen(_text_source) - strlen("Content-Length: ")); i++){
        memset(buff_info, 0x00, 17*sizeof(char));
        int8_t j=0;
        for (j=0; j<strlen("Content-Length: "); j++){
            buff_info[j] = _text_source[i + j];
        }
        if (strcmp(buff_info, "Content-Length: ") == 0){
            i = i + strlen("Content-Length: ");
            memset(buff_data, 0x00, 7*sizeof(char));
            for (int8_t j=0; j<6; j++){
                if (j>0 && (_text_source[i + j] < '0' || _text_source[i + j] > '9')){
                    free(buff_info);
                    return atoi(buff_data);
                }
                else if (_text_source[i + j] >= '0' && _text_source[i + j] <= '9'){
                    buff_data[j] = _text_source[i + j];
                }
            }
        }
        else if (i > 3){
            if (_text_source[i-3] == '\r' && _text_source[i-2] == '\n' && _text_source[i-1] == '\r' && _text_source[i] == '\n'){
                free(buff_info);
                return (int16_t)(strlen(_text_source) - i + 1);
            }
        }
    }
    free(buff_info);
    return 0;
}

static char *stcp_select_request(char *response, stcp_request_type _request_type){
    if (_request_type == STCP_REQ_COMPLETE){
        return response;
    }

    uint16_t i=0;
    char *http_status_response = (char *) malloc(60 * sizeof(char));
    if (http_status_response == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate http_status_response memory\n");
        return response;
    }

    memset(http_status_response, 0x00, 60*sizeof(char));
    for (i=0; i<strlen(response); i++){
        if (response[i] == '\n') break;
        http_status_response[i] = response[i];
    }
    http_status_response = (char *) realloc(http_status_response, (i+1)*sizeof(char));

    if (_request_type == STCP_REQ_HTTP_STATUS_ONLY){
        free(response);
        return http_status_response;
    }
    else if (strstr(http_status_response, "200") == NULL  && _request_type == STCP_REQ_CONTENT_BLOCKING_BY_STATUS){
        free(response);
        return http_status_response;
    }

    int16_t content_length = stcp_get_content_length(response);
    if (content_length == 0 || content_length > strlen(response)){
        free(response);
        return http_status_response;
    }

    char *response_tmp;
    if (_request_type == STCP_REQ_HEADER_ONLY){
        response_tmp = (char *) malloc((strlen(response) - content_length) - 1);
    }
    else if (_request_type == STCP_REQ_CONTENT_ONLY || _request_type == STCP_REQ_CONTENT_BLOCKING_BY_STATUS){
        response_tmp = (char *) malloc(content_length + 1);
    }

    if (response_tmp == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate temporary memory\n");
        free(response);
        return http_status_response;
    }

    free(http_status_response);

    if (_request_type == STCP_REQ_HEADER_ONLY){
        memset(response_tmp, 0x00, ((strlen(response) - content_length) - 1)*sizeof(char));
        for (i=0; i<(strlen(response) - content_length - 3); i++){
            response_tmp[i] = response[i];
        }
        free(response);
        return response_tmp;
    }

    else if (_request_type == STCP_REQ_CONTENT_ONLY || _request_type == STCP_REQ_CONTENT_BLOCKING_BY_STATUS){
        memset(response_tmp, 0x00, (content_length + 1)*sizeof(char));
        for (i=0; i<content_length; i++){
            response_tmp[i] = response[i + (strlen(response) - content_length)];
        }
        free(response);
        return response_tmp;
    }
    return NULL;
}

// PING PURPOSE
// run_without_root (do on shell) : setcap cap_net_raw+ep executable_file
static unsigned short stcp_checksum(void *b, int len){
	unsigned short *buff = b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 ) 
		sum += *buff++; 
	if ( len == 1 ) 
		sum += *(unsigned char*)buff; 
	sum = (sum >> 16) + (sum & 0xFFFF); 
	sum += (sum >> 16); 
	result = ~sum; 
	return result; 
} 

struct stcp_ping_summary stcp_ping(char *ADDRESS, uint16_t NUM_OF_PING){
    struct stcp_sock_data init_data;
    struct sockaddr_in servaddr;

    const int16_t PACKET_SIZE = 64;
    const uint16_t PING_DELAY = 1000;
    char ip_address[16];

    struct stcp_ping_summary ping_data;
    memset(&ping_data, 0x00, sizeof(struct stcp_ping_summary));

    init_data.socket_f = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (init_data.socket_f == -1) {
        stcp_debug(__func__, "CRITICAL", "socket creation failed...\n");
    }
    else{
        stcp_debug(__func__, "INFO", "Socket successfully created : %d\n", init_data.socket_f);
        memset(&servaddr, 0x00, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(22);
        if(stcp_check_ip(ADDRESS) != 0){
            struct hostent *host;
            host = gethostbyname(ADDRESS);
            if (host != NULL){
                servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
                strcpy(ip_address, inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
            }
            else {
                stcp_debug(__func__, "ERROR", "failed to get host by name\n", ADDRESS);
                stcp_close(&init_data);
                ping_data.state = -1;
                return ping_data;
            }
        }
        else {
            servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
            strcpy(ip_address, ADDRESS);
        }
    }

    struct ping_pkt 
    { 
	    struct icmphdr hdr; 
	    char msg[PACKET_SIZE-sizeof(struct icmphdr)]; 
    };

    struct ping_pkt pckt;
	struct sockaddr_in r_addr;
	struct timeval tv_out;
	struct timespec tm_start, tm_end;
    struct timespec tc_start, tc_end;
	int16_t ttl_val= (int16_t)PACKET_SIZE, msg_count=0, i;
    int16_t bytes = 0;
	long double total_tm_ping;
	socklen_t addr_len;

	tv_out.tv_sec = 2;
	tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tc_start);

	if (setsockopt(init_data.socket_f, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) 
	{
		stcp_debug(__func__, "CRITICAL", "Setting socket options to TTL failed!\n");
	}
	else
	{
		stcp_debug(__func__, "INFO", "Socket set to TTL\n");
	}

	// setting timeout of recv setting
	setsockopt(init_data.socket_f, SOL_SOCKET, SO_RCVTIMEO,(const char*)&tv_out, sizeof tv_out);

	while (msg_count < NUM_OF_PING){
		memset(&pckt, 0x00, sizeof(pckt));
		pckt.hdr.type = ICMP_ECHO;
		pckt.hdr.un.echo.id = getpid();
		
		for ( i = 0; i < sizeof(pckt.msg)-1; i++ ) pckt.msg[i] = i+'0'; 
		
		pckt.msg[i] = 0; 
		pckt.hdr.un.echo.sequence = msg_count++; 
		pckt.hdr.checksum = stcp_checksum(&pckt, sizeof(pckt)); 
		addr_len=sizeof(r_addr);

		//send packet
		clock_gettime(CLOCK_MONOTONIC, &tm_start);
		if (sendto(init_data.socket_f, &pckt, sizeof(pckt), 0, (struct sockaddr*) &servaddr, sizeof(servaddr)) <= 0) 
		{ 
			stcp_debug(__func__, "CRITICAL", "Packet Sending Failed!\n"); 
		} 
		//receive packet
		else if ((bytes = recvfrom(init_data.socket_f, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len)) <= 0 && msg_count>1) 
		{
            ping_data.tx_counter++;
			stcp_debug(__func__, "CRITICAL", "Packet receive failed!\n");
		}
		else {
            ping_data.tx_counter++;
			clock_gettime(CLOCK_MONOTONIC, &tm_end);
			total_tm_ping = (tm_end.tv_sec - tm_start.tv_sec)*1000.0;
			total_tm_ping = total_tm_ping + (tm_end.tv_nsec - tm_start.tv_nsec)/1000000.0;

			if(pckt.hdr.type!=69)
			{
				stcp_debug(__func__, "CRITICAL", "Error..Packet received with ICMP type %d code %d\n", pckt.hdr.type, pckt.hdr.code);
			}
            else if(pckt.hdr.code!=0){
                stcp_debug(__func__, "WARNING", "packet received (%d) with ICMP type %d code %d : %Lfms\n", bytes, pckt.hdr.type, pckt.hdr.code, total_tm_ping);
                if (ping_data.max_rtt < (uint16_t) total_tm_ping) {
                    ping_data.max_rtt = (uint16_t) total_tm_ping;
                }
                if (ping_data.min_rtt > (uint16_t) total_tm_ping || ping_data.min_rtt == 0){
                    ping_data.min_rtt = (uint16_t) total_tm_ping;
                }

				if (ping_data.avg_rtt == 0) ping_data.avg_rtt = (uint16_t) total_tm_ping;
				else ping_data.avg_rtt = (ping_data.avg_rtt + (uint16_t) total_tm_ping)/2;
            }
			else
			{
                ping_data.rx_counter++;
                if (ping_data.max_rtt < (uint16_t) total_tm_ping) {
                    ping_data.max_rtt = (uint16_t) total_tm_ping;
                }
                if (ping_data.min_rtt > (uint16_t) total_tm_ping || ping_data.min_rtt == 0){
                    ping_data.min_rtt = (uint16_t) total_tm_ping;
                }
				stcp_debug(__func__, "INFO", "%d bytes from (%s) msg_seq=%d ttl=%d rtt = %Lf ms\n", PACKET_SIZE, ip_address, msg_count, ttl_val, total_tm_ping);
				if (ping_data.avg_rtt == 0) ping_data.avg_rtt = (uint16_t) total_tm_ping;
				else ping_data.avg_rtt = (ping_data.avg_rtt + (uint16_t) total_tm_ping)/2;
			}
		}
		if (msg_count < NUM_OF_PING) usleep(PING_DELAY * 1000);
	}
    stcp_close(&init_data);

    clock_gettime(CLOCK_MONOTONIC, &tc_end);
	ping_data.time_counter = (tc_end.tv_sec - tc_start.tv_sec)*1000.0;
	ping_data.time_counter = ping_data.time_counter + (tc_end.tv_nsec - tc_start.tv_nsec)/1000000.0;

    ping_data.packet_loss = (100*(ping_data.tx_counter - ping_data.rx_counter))/ping_data.tx_counter;

    stcp_debug(__func__, "INFO", "\n"
     "  --- %s ping statistics ---\n"
     "  %d packet transmitted, %d received, %d%% packet loss, time %dms\n"
     "  rtt min/avg/max = %d/%d/%d ms\n",
     ADDRESS,
     ping_data.tx_counter, ping_data.rx_counter, ping_data.packet_loss, ping_data.time_counter,
     ping_data.min_rtt, ping_data.avg_rtt, ping_data.max_rtt
    );

    if (ping_data.packet_loss == 100){
        ping_data.state = -2;
        return ping_data;
    }

	return ping_data;
}