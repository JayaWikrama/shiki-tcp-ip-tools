/*
    lib info    : SHIKI_LIB_GROUP - TCP_IP
    ver         : 3.00.20.03.08
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
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include "shiki-tcp-ip-tools.h"

#ifdef __linux__
    #include <arpa/inet.h>
#endif
#ifdef __STCP_PING__
    #include <netinet/ip_icmp.h>
#endif

#define SA struct sockaddr
#define STCP_VER "3.00.20.03.08"

static const int8_t STCP_HEADER_CHECK = 0;
static const int8_t STCP_HEADER_PASS = 1;
static const int8_t STCP_HEADER_BLOCK = 2;
static const int8_t STCP_PROCESS_GET_HEADER = 3;
static const int8_t STCP_PROCESS_GET_CONTENT = 4;

uint16_t SIZE_PER_RECV = 128;

int8_t debug_mode_status = STCP_DEBUG_OFF;
int8_t infinite_retry_mode = WITHOUT_RETRY;
uint16_t time_out_in_seconds = 0;
uint16_t time_out_in_milliseconds = 0;
char stcp_file_name[STCP_MAX_LENGTH_FILE_NAME];

static void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...);
static int8_t stcp_check_ip(char *_ip_address);
static unsigned long stcp_get_content_length(char *_text_source);
static unsigned char *stcp_select_content(unsigned char *response, uint32_t _content_length);

static void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...){
	if (debug_mode_status == 1 || strcmp(debug_type, "INFO") != 0){
        struct tm *d_tm;
        struct timeval tm_debug;
        uint16_t msec = 0;
	    va_list aptr;
		
	    gettimeofday(&tm_debug, NULL);
	    d_tm = localtime(&tm_debug.tv_sec);
        msec = tm_debug.tv_usec/1000;
	
	    char* tmp_debug_msg;
        tmp_debug_msg = (char *) malloc(256*sizeof(char));
        if (tmp_debug_msg == NULL){
            printf("%02d-%02d-%04d %02d:%02d:%02d.%03i ERROR: %s: failed to allocate debug variable memory",
             d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec, msec, __func__
            );
            return;
        }
	    va_start(aptr, debug_msg);
	    vsprintf(tmp_debug_msg, debug_msg, aptr);
	    va_end(aptr);
        #ifdef __linux__
            if (strcmp(debug_type, "INFO")==0)
                printf("\033[1;32m%02d-%02d-%04d %02d:%02d:%02d.%03d\033[1;34m STCP\033[1;32m %s: %s: %s\033[0m",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, debug_type, function_name, tmp_debug_msg
                );
    	    else if (strcmp(debug_type, "WARNING")==0)
                printf("\033[1;33m%02d-%02d-%04d %02d:%02d:%02d.%03d\033[1;34m STCP\033[1;33m %s: %s: %s\033[0m",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, debug_type, function_name, tmp_debug_msg
                );
    	    else if (strcmp(debug_type, "ERROR")==0)
                printf("\033[1;31m%02d-%02d-%04d %02d:%02d:%02d.%03d\033[1;34m STCP\033[1;31m %s: %s: %s\033[0m",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, debug_type, function_name, tmp_debug_msg
                );
            else if (strcmp(debug_type, "CRITICAL")==0)
                printf("\033[1;31m%02d-%02d-%04d %02d:%02d:%02d.%03d\033[1;34m STCP\033[1;31m %s: %s: %s\033[0m",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, debug_type, function_name, tmp_debug_msg
                );
	    #else
            printf("%02d-%02d-%04d %02d:%02d:%02d.%03d %s: %s: %s",
             d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
             msec, debug_type, function_name, tmp_debug_msg
            );
        #endif
        free(tmp_debug_msg);
    }
}

static int8_t stcp_connect_with_timeout (int stcp_socket_f, struct sockaddr * addr, size_t addrlen, struct timeval * stcp_timeout) {
	int8_t retval, fcntl_flags;
	if ((fcntl_flags = fcntl (stcp_socket_f, F_GETFL, NULL)) < 0) {
		return -1;
	}
	if (fcntl (stcp_socket_f, F_SETFL, fcntl_flags | O_NONBLOCK) < 0) {
		return -1;
	}
	if ((retval = connect (stcp_socket_f, addr, addrlen)) < 0) {
		if (errno == EINPROGRESS) {
			fd_set wait_set;
			FD_ZERO (&wait_set);
			FD_SET (stcp_socket_f, &wait_set);
			retval = select (stcp_socket_f + 1, NULL, &wait_set, NULL, stcp_timeout);
		}
	}
	else {
		retval = 1;
	}

	if (fcntl (stcp_socket_f, F_SETFL, fcntl_flags) < 0) {
		return -1;
	}

	if (retval < 0) {
		return -1;
	}
	else if (retval == 0) {
		errno = ETIMEDOUT;
		return 1;
	}
	else {
		socklen_t len = sizeof (fcntl_flags);
		if (getsockopt (stcp_socket_f, SOL_SOCKET, SO_ERROR, &fcntl_flags, &len) < 0) {
			return -1;
		}
		if (fcntl_flags) {
			errno = fcntl_flags;
			return -1;
		}
	}
	return 0;
}

static int8_t stcp_check_ip(char *_ip_address){
    /* check length */
    if (strlen(_ip_address) > 15){
        return -1;
    }
    /* check point and value per point */
    int8_t point_counter = 0;
    int8_t aviable_value_per_point[4];
    aviable_value_per_point[0] = 0;
    aviable_value_per_point[1] = 0;
    aviable_value_per_point[2] = 0;
    aviable_value_per_point[3] = 0;
    int8_t i = 0;
    for (i=0; i<strlen(_ip_address); i++){
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

long stcp_get_version(char *_version){
    strcpy(_version, STCP_VER);
    long version_in_long = 0;
    uint8_t idx_ver = 0;
    uint8_t multiplier = 10;
    while(idx_ver < 13){
        if(STCP_VER[idx_ver] != '.' && STCP_VER[idx_ver] != 0x00){
            if (version_in_long == 0){
                version_in_long = STCP_VER[idx_ver] - '0';
            }
            else{
                version_in_long = (version_in_long*multiplier) + (STCP_VER[idx_ver] - '0');
            }
        }
        else if (STCP_VER[idx_ver] == 0x00){
            break;
        }
        idx_ver++;
    }
    return version_in_long;
}

void stcp_view_version(){
    stcp_debug(__func__, "VERSION", "%s\n", STCP_VER);
}

int8_t stcp_setup(stcp_setup_parameter _setup_parameter, int16_t _value){
    if (_setup_parameter == STCP_SET_TIMEOUT_IN_SEC){
        if (_value < 0 || _value > 999){
            stcp_debug(__func__, "WARNING", "invalid value\n");
            return -1;
        }
        time_out_in_seconds = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_TIMEOUT_IN_MILLISEC){
        if (_value < 0 || _value > 999){
            stcp_debug(__func__, "WARNING", "invalid value\n");
            return -1;
        }
        time_out_in_milliseconds = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_DEBUG_MODE){
        if ((int8_t)_value == STCP_DEBUG_ON || (int8_t)_value == STCP_DEBUG_OFF){
            debug_mode_status = (int8_t)_value;
        }
        else {
            stcp_debug(__func__, "WARNING", "wrong value\n");
            return -1;
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
            return -1;
        }
    }
    else {
        stcp_debug(__func__, "WARNING", "wrong parameters\n");
        return -1;
    }
    return 0;
}

int8_t stcp_set_download_file_name(char* _file_name){
    if (strlen(_file_name) > STCP_MAX_LENGTH_FILE_NAME){
        stcp_debug(__func__, "WARNING", "file name to long. max:%d character\n", STCP_MAX_LENGTH_FILE_NAME);
        return -1;
    }
    strcpy(stcp_file_name, _file_name);
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

            if (time_out_in_seconds > 0 || time_out_in_milliseconds > 0){
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

            if (time_out_in_seconds > 0 || time_out_in_milliseconds > 0){
                struct timeval tv;
                tv.tv_sec = time_out_in_seconds;
                tv.tv_usec = time_out_in_milliseconds * 1000;
                setsockopt(init_data.socket_f, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
            }

            stcp_debug(__func__, "INFO", "waiting for server...\n");
            if (time_out_in_seconds > 0 || time_out_in_milliseconds > 0){
                int8_t retval = 0;
                struct timeval tv;
                tv.tv_sec = time_out_in_seconds;
                tv.tv_usec = time_out_in_milliseconds * 1000;
                retval = stcp_connect_with_timeout(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr), &tv);
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

#ifdef __STCP_SSL__
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

            if (time_out_in_seconds > 0 || time_out_in_milliseconds > 0){
                struct timeval tv;
                tv.tv_sec = time_out_in_seconds;
                tv.tv_usec = time_out_in_milliseconds * 1000;
                setsockopt(init_data.socket_f, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
            }

            stcp_debug(__func__, "INFO", "waiting for server...\n");
            if (time_out_in_seconds > 0 || time_out_in_milliseconds > 0){
                int8_t retval = 0;
                struct timeval tv;
                tv.tv_sec = time_out_in_seconds;
                tv.tv_usec = time_out_in_milliseconds * 1000;
                retval = stcp_connect_with_timeout(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr), &tv);
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
#endif

int16_t stcp_send_data(struct stcp_sock_data com_data, unsigned char* buff, int16_t size_set){
    int16_t bytes;
    bytes = write(com_data.connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to send %d data\n", bytes);
    else if (time_out_in_seconds > 0 || time_out_in_milliseconds > 0){
        stcp_debug(__func__, "WARNING", "send %d data. request timeout\n", bytes);
    }
    return bytes;
}

int16_t stcp_recv_data(struct stcp_sock_data com_data, unsigned char* buff, int16_t size_set){
    int16_t bytes;
    bytes = read(com_data.connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to receive %d data\n", bytes);
    else if (time_out_in_seconds > 0 || time_out_in_milliseconds > 0){
        stcp_debug(__func__, "WARNING", "receive %d data. request timeout or finished\n", bytes);
    }
    return bytes;
}

#ifdef __STCP_SSL__
int16_t stcp_ssl_send_data(struct stcp_sock_data com_data, unsigned char* buff, int16_t size_set){
    int16_t bytes;
    bytes = SSL_write(com_data.ssl_connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to send %d data\n", bytes);
    else if (time_out_in_seconds > 0 || time_out_in_milliseconds > 0){
        stcp_debug(__func__, "WARNING", "send %d data. request timeout\n", bytes);
    }
    return bytes;
}

int16_t stcp_ssl_recv_data(struct stcp_sock_data com_data, unsigned char* buff, int16_t size_set){
    int16_t bytes;
    bytes = SSL_read(com_data.ssl_connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to receive %d data\n", bytes);
    else if (time_out_in_seconds > 0 || time_out_in_milliseconds > 0){
        stcp_debug(__func__, "WARNING", "receive %d data. request timeout or finished\n", bytes);
    }
    return bytes;
}
#endif

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

char *stcp_http_content_generator(uint16_t _sizeof_content, char *_content_format, ...){
    char *stcp_content = NULL;
    stcp_content = (char *) malloc(_sizeof_content*sizeof(char));
    if (stcp_content == NULL){
        stcp_debug(__func__, "WARNING", "failed to allocate stcp_content memory\n");
        return NULL;
    }
    va_list aptr;
	va_start(aptr, _content_format);
	vsprintf(stcp_content, _content_format, aptr);
	va_end(aptr);

    if ((strlen(stcp_content) + 1) != _sizeof_content){
        if ((strlen(stcp_content) + 1) > _sizeof_content){
            stcp_debug(__func__, "WARNING", "size input to small\n");
        }
        stcp_content = (char *) realloc(stcp_content, (strlen(stcp_content) + 1));
    }
    return stcp_content;
}

unsigned char *stcp_http_request(char *_req_type, char *_url, char *_header, char *_content, stcp_request_type _request_type){
    char *message_request;
    char *host;
    char *end_point;
    unsigned char *response;
    char *protocol;
    uint16_t length_of_message = 0;
    uint16_t port = 0;

    FILE *download_file = NULL;
    uint8_t try_times = 0;

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
    response = (unsigned char *) malloc(2 * sizeof(unsigned char));
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
        #ifdef __STCP_SSL__
        socket_f = stcp_ssl_client_init(host, port);
        #else
        stcp_debug(__func__, "WARNING", "please enable __STCP_SSL__ on shiki-tcp-ip-tools.h\n");
        free(message_request);
        free(host);
        free(end_point);
        free(protocol);
        free(response);
        return NULL;
        #endif
    }
    if (socket_f.socket_f <= 0){
        free(message_request);
        free(host);
        free(end_point);
        free(protocol);
        response = (unsigned char *) realloc(response, 17*sizeof(unsigned char));
        strcpy((char *) response, "no route to host");
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

    if (_request_type == STCP_REQ_DOWNLOAD_CONTENT){
        if (strlen(stcp_file_name) == 0){
            char stcp_file_name_tmp[sizeof(stcp_file_name)];
            uint16_t idx_stcp_file_name = 0;
            memset(stcp_file_name, 0x00, sizeof(stcp_file_name));
            memset(stcp_file_name_tmp, 0x00, sizeof(stcp_file_name_tmp));
            for (idx_stcp_file_name = 0; idx_stcp_file_name<strlen(end_point); idx_stcp_file_name++){
                if (end_point[strlen(end_point) - 1 - idx_stcp_file_name] == '/' || idx_stcp_file_name == STCP_MAX_LENGTH_FILE_NAME - 1){
                    break;
                }
                stcp_file_name_tmp[idx_stcp_file_name] = end_point[strlen(end_point) - 1 - idx_stcp_file_name];
            }
            for (idx_stcp_file_name=0; idx_stcp_file_name<strlen(stcp_file_name_tmp); idx_stcp_file_name++){
                stcp_file_name[idx_stcp_file_name] = stcp_file_name_tmp[strlen(stcp_file_name_tmp) - 1 - idx_stcp_file_name];
            }
        }

        try_times = 3;
        do{
    	    download_file = fopen(stcp_file_name, "r");
            try_times--;
        } while (download_file == NULL && try_times > 0);

        if (download_file != NULL){
            stcp_debug(__func__, "WARNING", "file already exist. process: remove existing file\n");
            fclose(download_file);
            download_file = NULL;
            remove(stcp_file_name);
        }

        try_times = 3;
        do{
    	    download_file = fopen(stcp_file_name, "a");
            try_times--;
        } while (download_file == NULL && try_times > 0);
    }

    if (strcmp(protocol, "http") == 0){
        stcp_send_data(socket_f, (unsigned char *) message_request, strlen(message_request));
    }
    else {
        #ifdef __STCP_SSL__
        stcp_ssl_send_data(socket_f, (unsigned char *) message_request, strlen(message_request));
        #endif
    }

    free(message_request);
    free(host);
    free(end_point);

    int16_t bytes = 0;
    int16_t total_bytes = 0;
    int8_t header_check_status = STCP_HEADER_CHECK;
    int8_t get_process = STCP_PROCESS_GET_HEADER;
    uint32_t content_length = 0;
    uint32_t download_counter = 0;
    memset(response, 0x00, 2 * sizeof(char));
    do {
        unsigned char response_tmp[SIZE_PER_RECV + 1];
        memset(response_tmp, 0x00, SIZE_PER_RECV + 1);
        if (get_process == STCP_PROCESS_GET_HEADER){
            if (strcmp(protocol, "http") == 0){
                bytes = stcp_recv_data(socket_f, response_tmp, 1);
            }
            else {
                #ifdef __STCP_SSL__
                bytes = stcp_ssl_recv_data(socket_f, response_tmp, 1);
                #endif
            }
            if (bytes == -1){
                if (strlen((char *)response) < 5 && SIZE_PER_RECV > 1)
                stcp_debug(__func__, "ERROR", "Lost Connection\n");
                break;
            }
            else if (bytes == 0){
                break;
            }
        }
        else if (STCP_PROCESS_GET_CONTENT){
            if (strcmp(protocol, "http") == 0){
                bytes = stcp_recv_data(socket_f, response_tmp, SIZE_PER_RECV);
            }
            else {
                #ifdef __STCP_SSL__
                bytes = stcp_ssl_recv_data(socket_f, response_tmp, SIZE_PER_RECV);
                #endif
            }
            if (bytes == -1){
                stcp_debug(__func__, "ERROR", "Lost Connection\n");
                break;
            }
            else if (bytes == 0){
                break;
            }
        }
        if (_request_type != STCP_REQ_DOWNLOAD_CONTENT || get_process == STCP_PROCESS_GET_HEADER){
            total_bytes = total_bytes + bytes;
            response = (unsigned char *) realloc(response, (total_bytes + 1) * sizeof(unsigned char));
            memcpy(response + (total_bytes - bytes), response_tmp, bytes);
            response[total_bytes] = 0x00;
            if (get_process == STCP_PROCESS_GET_HEADER){
                if( response[total_bytes - 1] == '\n' && response[total_bytes - 2] == '\r' &&
                 response[total_bytes - 3] == '\n' && response[total_bytes - 4] == '\r'
                ){
                    if (_request_type == STCP_REQ_HEADER_ONLY){
                        break;
                    }
                    get_process = STCP_PROCESS_GET_CONTENT;
                    content_length = stcp_get_content_length((char *) response);
                }
                if (response_tmp[0] == '\n' && header_check_status == STCP_HEADER_CHECK){
                    if (strstr((char *) response, "200 OK") == NULL){
                        header_check_status = STCP_HEADER_BLOCK;
                        break;
                    }
                    else if (_request_type == STCP_REQ_HTTP_STATUS_ONLY){
                        break;
                    }
                    else {
                        header_check_status = STCP_HEADER_PASS;
                    }
                }
            }
            else {
                download_counter = download_counter + bytes;
                if (content_length > 0){
                    stcp_debug(__func__, "INFO", "get: %i/%i bytes\n", download_counter, content_length);
                }
                else {
                    stcp_debug(__func__, "INFO", "get: %i/unknown bytes\n", download_counter);
                }
            }
        }
        else if (_request_type == STCP_REQ_DOWNLOAD_CONTENT && get_process == STCP_PROCESS_GET_CONTENT){
            download_counter = download_counter + bytes;
            if (download_counter%10 == 0){
                if (content_length > 0){
                    stcp_debug(__func__, "INFO", "downloaded: %i/%i bytes\n", download_counter, content_length);
                }
                else {
                    stcp_debug(__func__, "INFO", "downloaded: %i/unknown bytes\n", download_counter);
                }
            }

            /* append file */
            if (download_file == NULL){
                stcp_debug(__func__, "ERROR", "failed to open config file\n");
            }
            else {
                fprintf(download_file, "%s", response_tmp);
            }
        }

        if (content_length > 0 && download_counter == content_length){
            break;
        }
    } while (bytes >= 1);
    if (strcmp(protocol, "http") == 0){
        stcp_close(&socket_f);
    }
    else {
        #ifdef __STCP_SSL__
        stcp_ssl_close(&socket_f);
        #endif
    }
    free(protocol);
    if (_request_type == STCP_REQ_DOWNLOAD_CONTENT){
        memset(stcp_file_name, 0x00, sizeof(stcp_file_name));
        if (download_file != NULL){
            fclose(download_file);
        }
        if (content_length > 0){
            if (download_counter == content_length){
                stcp_debug(__func__, "DOWNLOAD", "downloaded finished: %i/%i bytes\n", download_counter, content_length);
            }
            else {
                stcp_debug(__func__, "DOWNLOAD", "downloaded unfinished: %i/%i bytes\n", download_counter, content_length);
            }
        }
        else {
            stcp_debug(__func__, "DOWNLOAD", "downloaded finished: %i/unknown bytes\n", __func__, download_counter);
        }
    }
    if (strlen((char *) response) == 0){
        if (time_out_in_seconds == 0){
            response = (unsigned char *) realloc(response, 30*sizeof(unsigned char));
            strcpy((char *) response, "bad connection or bad request");
            return response;
        }
        else {
            response = (unsigned char *) realloc(response, 16*sizeof(unsigned char));
            strcpy((char *) response, "request timeout");
            return response;
        }
    }
    if (header_check_status == STCP_HEADER_BLOCK || _request_type != STCP_REQ_CONTENT_ONLY){
        return response;
    }
    return stcp_select_content(response, download_counter);
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

#ifdef __STCP_SSL__
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
#endif

static unsigned long stcp_get_content_length(char *_text_source){
    char *buff_info;
    do {
        buff_info = (char *) malloc(17*sizeof(char));
        if (buff_info == NULL){
            stcp_debug(__func__, "WARNING", "failed to allocate memory\n");
            usleep(1000);
        }
    } while (buff_info == NULL);
    char buff_data[10];
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
            int8_t j = 0;
            for (j=0; j<9; j++){
                if (j>0 && (_text_source[i + j] < '0' || _text_source[i + j] > '9')){
                    free(buff_info);
                    return (unsigned long) atol(buff_data);
                }
                else if (_text_source[i + j] >= '0' && _text_source[i + j] <= '9'){
                    buff_data[j] = _text_source[i + j];
                }
            }
        }
    }
    free(buff_info);
    return 0;
}

static unsigned char *stcp_select_content(unsigned char *response, uint32_t _content_length){
    if (_content_length == 0){
        free(response);
        response = NULL;
        return NULL;
    }
    unsigned char *response_tmp;
    response_tmp = (unsigned char *) malloc((_content_length + 1) *sizeof(unsigned char));
    if (response_tmp == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate temporary memory\n");
        free(response);
        response = NULL;
        return NULL;
    }
    memset(response_tmp, 0x00, (_content_length + 1)*sizeof(char));
    uint32_t i = 0;
    for (i=0; i<_content_length; i++){
        response_tmp[i] = response[i + (strlen((char *) response) - _content_length)];
    }
    free(response);
    response = NULL;
    return response_tmp;

}

/*
PING PURPOSE
run_without_root (do on shell) : setcap cap_net_raw+ep executable_file
*/
#ifdef __STCP_PING__
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
	struct timeval tm_start, tm_end;
    struct timeval tc_start, tc_end;
	int16_t ttl_val= (int16_t)PACKET_SIZE, msg_count=0, i;
    int16_t bytes = 0;
	long double total_tm_ping;
	socklen_t addr_len;

	tv_out.tv_sec = 2;
	tv_out.tv_usec = 0;

    gettimeofday(&tc_start, NULL);

	if (setsockopt(init_data.socket_f, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) 
	{
		stcp_debug(__func__, "CRITICAL", "Setting socket options to TTL failed!\n");
	}
	else
	{
		stcp_debug(__func__, "INFO", "Socket set to TTL\n");
	}

	/* setting timeout of recv setting */
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

		/* send packet */
		gettimeofday(&tm_start, NULL);
		if (sendto(init_data.socket_f, &pckt, sizeof(pckt), 0, (struct sockaddr*) &servaddr, sizeof(servaddr)) <= 0) 
		{ 
			stcp_debug(__func__, "CRITICAL", "Packet Sending Failed!\n"); 
		} 
		/* receive packet */
		else if ((bytes = recvfrom(init_data.socket_f, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len)) <= 0 && msg_count>1) 
		{
            ping_data.tx_counter++;
			stcp_debug(__func__, "CRITICAL", "Packet receive failed!\n");
		}
		else {
            ping_data.tx_counter++;
			gettimeofday(&tm_end, NULL);
			total_tm_ping = (tm_end.tv_sec - tm_start.tv_sec)*1000.0;
			total_tm_ping = total_tm_ping + (tm_end.tv_usec - tm_start.tv_usec)/1000.0;

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

    gettimeofday(&tc_end, NULL);
	ping_data.time_counter = (tc_end.tv_sec - tc_start.tv_sec)*1000.0;
	ping_data.time_counter = ping_data.time_counter + (tc_end.tv_usec - tc_start.tv_usec)/1000.0;

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

#endif