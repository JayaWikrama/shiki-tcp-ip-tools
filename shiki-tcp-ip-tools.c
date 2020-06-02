/*
    lib info    : SHIKI_LIB_GROUP - TCP_IP
    ver         : 3.07.20.06.02
    author      : Jaya Wikrama, S.T.
    e-mail      : jayawikrama89@gmail.com
    Copyright (c) 2019 HANA,. Jaya Wikrama

    Support     : tcp-ip client/server
                : tcp-ip ssl client
                : http request
                : webserver (http/tcp)
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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include "shiki-tcp-ip-tools.h"

#ifndef TIOCOUTQ
#define TIOCOUTQ _IOR('t', 115, int)
#endif

#ifdef __linux__
    #include <arpa/inet.h>
#endif
#ifdef __STCP_PING__
    #include <netinet/ip_icmp.h>
#endif
#ifdef __STCP_WEBSERVER__
    #include "shiki-tcp-ip-userdef.h"
#endif

#define SA struct sockaddr
#define STCP_VER "3.07.20.06.02"

typedef enum {
    #ifdef __STCP_WEBSERVER__
    /* Server state */
    STCP_SERVER_RUNING = 0x00,
    STCP_SERVER_STOP = 0x01,
    STCP_SERVER_STOPED = 0x02,
    #endif
    /* Data com type */
    STCP_TCP = 0x0a,
    STCP_SSL = 0x0b,
    /* Process state */
    STCP_HEADER_CHECK = 0x10,
    STCP_HEADER_PASS = 0x11,
    STCP_HEADER_BLOCK = 0x12,
    STCP_PROCESS_GET_HEADER = 0x13,
    STCP_PROCESS_GET_CONTENT = 0x14
} stcp_const;

struct stcp_setup_var{
    int8_t stcp_debug_mode;
    int8_t stcp_retry_mode;
    uint8_t stcp_max_recv_try;
    uint16_t stcp_timeout_sec;
    uint16_t stcp_timeout_millisec;
    uint16_t stcp_keepalive_sec;
    uint16_t stcp_keepalive_millisec;
    uint32_t stcp_size_per_recv;
    uint32_t stcp_size_per_send;
};

struct stcp_setup_var stcp_setup_data = {
    STCP_DEBUG_OFF,
    WITHOUT_RETRY,
    3,
    0,
    0,
    0,
    0,
    128,
    128
};

#ifdef __STCP_WEBSERVER__
int8_t stcp_webserver_init_state = 0;
int8_t stcp_server_state = 0;
#endif

char stcp_file_name[STCP_MAX_LENGTH_FILE_NAME];

static int8_t stcp_check_ip(char *_ip_address);
static unsigned long stcp_get_content_length(char *_text_source);
static unsigned char *stcp_select_content(unsigned char *response, uint32_t _content_length);

void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...){
	if (stcp_setup_data.stcp_debug_mode == 1 || strcmp(debug_type, "INFO") != 0){
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
            if (strcmp(debug_type, "WEBSERVER INFO")==0)
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
        tmp_debug_msg = NULL;
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

static int8_t stcp_accept_with_timeout (int stcp_socket_f, struct sockaddr_in *addr, socklen_t *addrlen, struct timeval * stcp_timeout) {
	int8_t retval, fcntl_flags;
    int connf = 0;
	if ((fcntl_flags = fcntl (stcp_socket_f, F_GETFL, NULL)) < 0) {
		return -1;
	}
	if (fcntl (stcp_socket_f, F_SETFL, fcntl_flags | O_NONBLOCK) < 0) {
		return -1;
	}
	if ((connf = accept(stcp_socket_f, (SA*)addr, addrlen)) < 0) {
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
	return connf;
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

int8_t stcp_setup(stcp_setup_parameter _setup_parameter, uint32_t _value){
    if (_setup_parameter == STCP_SET_TIMEOUT_IN_SEC){
        if (_value < 0 || _value > 999){
            stcp_debug(__func__, "WARNING", "invalid value\n");
            return -1;
        }
        stcp_setup_data.stcp_timeout_sec = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_TIMEOUT_IN_MILLISEC){
        if (_value < 0 || _value > 999){
            stcp_debug(__func__, "WARNING", "invalid value\n");
            return -1;
        }
        stcp_setup_data.stcp_timeout_millisec = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_KEEP_ALIVE_TIMEOUT_IN_SEC){
        if (_value < 0 || _value > 30){
            stcp_debug(__func__, "WARNING", "invalid value\n");
            return -1;
        }
        stcp_setup_data.stcp_timeout_sec = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_KEEP_ALIVE_TIMEOUT_IN_MILLISEC){
        if (_value < 0 || _value > 999){
            stcp_debug(__func__, "WARNING", "invalid value\n");
            return -1;
        }
        stcp_setup_data.stcp_timeout_millisec = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_DEBUG_MODE){
        if ((int8_t)_value == STCP_DEBUG_ON || (int8_t)_value == STCP_DEBUG_OFF){
            stcp_setup_data.stcp_debug_mode = (int8_t)_value;
        }
        else {
            stcp_debug(__func__, "WARNING", "wrong value\n");
            return -1;
        }
    }
    else if(_setup_parameter == STCP_SET_SIZE_PER_RECV){
        stcp_setup_data.stcp_size_per_recv = (uint32_t) _value;
    }
    else if(_setup_parameter == STCP_SET_SIZE_PER_SEND){
        stcp_setup_data.stcp_size_per_send = (uint32_t) _value;
    }
    else if (_setup_parameter == STCP_SET_INFINITE_MODE_RETRY){
        if ((int8_t)_value == INFINITE_RETRY || (int8_t)_value == WITHOUT_RETRY){
            stcp_setup_data.stcp_retry_mode = (int8_t)_value;
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

stcpSock stcp_server_init(char *ADDRESS, uint16_t PORT){
    stcpSock init_data;
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
            const int optVal = 1;
            const socklen_t optLen = sizeof(optVal);
            setsockopt(init_data.socket_f, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen);
            
            if ((bind(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
                stcp_debug(__func__, "CRITICAL", "socket bind failed...\n");
                if (stcp_setup_data.stcp_retry_mode == 1) stcp_debug(__func__, "INFO", "trying to create a socket...\n");
                retval = -2; 
                close(init_data.socket_f);
                init_data.socket_f = 0;
                sleep(1);
            }
            else{
                stcp_debug(__func__, "INFO", "Socket successfully binded..\n");

                if ((listen(init_data.socket_f, 5)) != 0) { 
                    stcp_debug(__func__, "CRITICAL", "Listen failed...\n");
                    retval = -3;
                    close(init_data.socket_f);
                    init_data.socket_f = 0;
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
                        if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
                            struct timeval tv;
                            tv.tv_sec = stcp_setup_data.stcp_timeout_sec;
                            tv.tv_usec = 0;
                            setsockopt(init_data.connection_f, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
                        }
                    }
                }
            }
        }
    } while (retval < 0 && stcp_setup_data.stcp_retry_mode == INFINITE_RETRY);
    return init_data;
}

#ifdef __STCP_WEBSERVER__
int8_t stcp_http_webserver_init(stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList *_stcpWList){
    stcpWInfo stcpWI;
    stcpWHead stcpWH;

    stcpWI.server_header = NULL;
    stcpWI.rcv_header = NULL;
    stcpWI.rcv_endpoint = NULL;
    stcpWI.rcv_content_type = NULL;
    stcpWI.rcv_acception_type = NULL;
    stcpWI.rcv_auth = NULL;
    stcpWI.rcv_cookies = NULL;
    stcpWI.rcv_connection_type = NULL;
    stcpWI.rcv_content = NULL;
    stcpWH.content_type = NULL;
    stcpWH.accept_type = NULL;

    *_stcpWList = NULL;
    stcpWI.server_header = (char *) malloc(8*sizeof(char));
    if (stcpWI.server_header == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate server_header memory\n");
        return -1;
    }
    stcpWI.auth_end_point = (char *) malloc(8*sizeof(char));
    if (stcpWI.auth_end_point == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate auth_end_point memory\n");
        goto stcp_err_1;
    }
    stcpWI.rcv_header = (char *) malloc(8*sizeof(char));
    if (stcpWI.rcv_header == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate rcv_header memory\n");
        goto stcp_err_2;
    }
    stcpWI.rcv_endpoint = (char *) malloc(8*sizeof(char));
    if (stcpWI.rcv_endpoint == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate rcv_endpoint memory\n");
        goto stcp_err_3;
    }
    stcpWI.rcv_content_type = (char *) malloc(8*sizeof(char));
    if (stcpWI.rcv_content_type == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate rcv_content_type memory\n");
        goto stcp_err_4;
    }
    stcpWI.rcv_acception_type = (char *) malloc(8*sizeof(char));
    if (stcpWI.rcv_acception_type == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate rcv_acception_type memory\n");
        goto stcp_err_5;
    }
    stcpWI.rcv_auth = (char *) malloc(8*sizeof(char));
    if (stcpWI.rcv_auth == NULL){
        goto stcp_err_6;
    }
    stcpWI.rcv_cookies = (char *) malloc(8*sizeof(char));
    if (stcpWI.rcv_cookies == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate rcv_cookies memory\n");
        goto stcp_err_7;
    }
    stcpWI.rcv_connection_type = (char *) malloc(8*sizeof(char));
    if (stcpWI.rcv_connection_type == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate rcv_connection_type memory\n");
        goto stcp_err_8;
    }
    stcpWI.rcv_content = (char *) malloc(8*sizeof(char));
    if (stcpWI.rcv_content == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate rcv_content memory\n");
        goto stcp_err_9;
    }
    stcpWI.ipaddr = (char *) malloc(16*sizeof(char));
    if (stcpWI.ipaddr == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate ipaddr memory\n");
        goto stcp_err_10;
    }
    stcpWH.content_type = (char *) malloc(32*sizeof(char));
    if (stcpWH.content_type == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate content_type memory\n");
        goto stcp_err_11;
    }
    stcpWH.accept_type = (char *) malloc(8*sizeof(char));
    if (stcpWH.accept_type == NULL){
        stcp_debug(__func__, "ERROR", "failed to alllocate accept_type memory\n");
        goto stcp_err_12;
    }

    strcpy(stcpWH.content_type, "text/html; charset=ISO-8859-1");
    strcpy(stcpWH.accept_type, "*/*");
    stcp_webserver_init_state = 1;

    *_stcpWI = stcpWI;
    *_stcpWH = stcpWH;

    return 0;

    stcp_err_12:
        free(stcpWH.content_type);
        stcpWH.content_type = NULL;
    stcp_err_11:
        free(stcpWI.ipaddr);
        stcpWI.ipaddr = NULL;
    stcp_err_10:
        free(stcpWI.rcv_content);
        stcpWI.rcv_content = NULL;
    stcp_err_9:
        free(stcpWI.rcv_connection_type);
        stcpWI.rcv_connection_type = NULL;
    stcp_err_8:
        free(stcpWI.rcv_cookies);
        stcpWI.rcv_cookies = NULL;
    stcp_err_7:
        free(stcpWI.rcv_auth);
        stcpWI.rcv_auth = NULL;
    stcp_err_6:
        free(stcpWI.rcv_acception_type);
        stcpWI.rcv_acception_type = NULL;
    stcp_err_5:
        free(stcpWI.rcv_content_type);
        stcpWI.rcv_content_type = NULL;
    stcp_err_4:
        free(stcpWI.rcv_endpoint);
        stcpWI.rcv_endpoint = NULL;
    stcp_err_3:
        free(stcpWI.rcv_header);
        stcpWI.rcv_header = NULL;
    stcp_err_2:
        free(stcpWI.auth_end_point);
        stcpWI.auth_end_point = NULL;
    stcp_err_1:
        free(stcpWI.server_header);
        stcpWI.server_header = NULL;
        return -1;
}

static void stcp_http_webserver_bzero(stcpWInfo *_stcpWI, stcpWHead *_stcpWH){
    _stcpWI->rcv_header = (char *) realloc(_stcpWI->rcv_header, 8*sizeof(char));
    _stcpWI->rcv_endpoint = (char *) realloc(_stcpWI->rcv_endpoint, 8*sizeof(char));
    _stcpWI->rcv_content_type = (char *) realloc(_stcpWI->rcv_content_type, 8*sizeof(char));
    _stcpWI->rcv_acception_type = (char *) realloc(_stcpWI->rcv_acception_type, 8*sizeof(char));
    _stcpWI->rcv_auth = (char *) realloc(_stcpWI->rcv_auth, 8*sizeof(char));
    _stcpWI->rcv_cookies = (char *) realloc(_stcpWI->rcv_cookies, 8*sizeof(char));
    _stcpWI->rcv_connection_type = (char *) realloc(_stcpWI->rcv_connection_type, 8*sizeof(char));
    _stcpWI->rcv_content = (char *) realloc(_stcpWI->rcv_content, 8*sizeof(char));

    memset(_stcpWI->rcv_header, 0x00, 8*sizeof(char));
    memset(_stcpWI->rcv_endpoint, 0x00, 8*sizeof(char));
    memset(_stcpWI->rcv_content_type, 0x00, 8*sizeof(char));
    memset(_stcpWI->rcv_acception_type, 0x00, 8*sizeof(char));
    memset(_stcpWI->rcv_auth, 0x00, 8*sizeof(char));
    memset(_stcpWI->rcv_cookies, 0x00, 8*sizeof(char));
    memset(_stcpWI->rcv_connection_type, 0x00, 8*sizeof(char));
    memset(_stcpWI->rcv_content, 0x00, 8*sizeof(char));

    _stcpWI->content_length = 0;
}

static void stcp_http_webserver_free(stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList *_stcpWList){
    free(_stcpWI->server_header);
    free(_stcpWI->auth_end_point);
    free(_stcpWI->rcv_header);
    free(_stcpWI->rcv_endpoint);
    free(_stcpWI->rcv_content_type);
    free(_stcpWI->rcv_acception_type);
    free(_stcpWI->rcv_auth);
    free(_stcpWI->rcv_cookies);
    free(_stcpWI->rcv_connection_type);
    free(_stcpWI->rcv_content);
    free(_stcpWI->ipaddr);
    free(_stcpWH->content_type);
    free(_stcpWH->accept_type);

    _stcpWI->server_header = NULL;
    _stcpWI->auth_end_point = NULL;
    _stcpWI->rcv_header = NULL;
    _stcpWI->rcv_endpoint = NULL;
    _stcpWI->rcv_content_type = NULL;
    _stcpWI->rcv_acception_type = NULL;
    _stcpWI->rcv_auth = NULL;
    _stcpWI->rcv_cookies = NULL;
    _stcpWI->rcv_content = NULL;
    _stcpWI->content_length = 0;
    _stcpWI->rcv_content = NULL;
    _stcpWI->rcv_connection_type = NULL;
    _stcpWI->ipaddr = NULL;
    _stcpWH->content_type = NULL;
    _stcpWH->accept_type = NULL;

    shilink_free(_stcpWList);
    *_stcpWList = NULL;
}

static int8_t stcp_http_webserver_header_get(unsigned char *_source_text, unsigned char *_specific_word, unsigned char **_return, unsigned char _end_code){
    uint16_t len_buff = strlen((char *) _source_text);
    unsigned char buff_tmp[strlen((char *) _specific_word) + 3];
    uint16_t idx_char = 0;
    uint16_t buffer_size = 8;
    uint16_t content_size = 2;
    uint16_t idx_add = 0;
	while (idx_char<=len_buff){
        memset(buff_tmp, 0x00, sizeof(buff_tmp));
        idx_add = 0;
        while(_source_text[idx_char] != ' ' &&
         _source_text[idx_char] != '\n' &&
         _source_text[idx_char] != 0x00 &&
         strlen((char *) buff_tmp) < (sizeof(buff_tmp)-1)
        ){
            buff_tmp[idx_add]=_source_text[idx_char];
            idx_char++;
            idx_add++;
        }
        idx_char++;
        if(memcmp(buff_tmp, _specific_word, strlen((char *) _specific_word)) == 0 && len_buff-idx_char > 2){
			uint16_t i = 0;
            for (i=idx_char; i<len_buff; i++){
                if(_source_text[i] != _end_code){
                    if (buffer_size < content_size + 1){
                        buffer_size = buffer_size + 8;
                        *_return = (unsigned char *) realloc(*_return, buffer_size * sizeof(char));
                    }
                    (*_return)[i-idx_char] = _source_text[i];
                    (*_return)[(i-idx_char) + 1] = 0x00;
                    content_size++;
                }
                else {
                    break;
                }
            }
            return 0;
            break;
        }
    }
    return -1;
}

void stcp_http_webserver_header_parser(stcpWInfo *_stcpWI){
    uint16_t idx_char = 0;
    uint16_t buffer_size = 8;
    uint16_t content_size = 0;
    uint16_t idx_content = 0;

    stcp_debug(__func__, "WEBSERVER INFO", "HEADER\n");
    printf("%s\n", _stcpWI->rcv_header);
    memset(_stcpWI->request, 0x00, sizeof(_stcpWI->request));
    /* GET REQUEST TYPE */
    idx_content = 0;
    while (_stcpWI->rcv_header[idx_char] != ' ' && _stcpWI->rcv_header[idx_char] != 0x00){
        if (idx_content < sizeof(_stcpWI->request) - 1){
            _stcpWI->request[idx_content] = _stcpWI->rcv_header[idx_char];
        }
        idx_char++;
        idx_content++;
    }
    idx_char++;
    content_size = 2;
    idx_content = 0;
    stcp_debug(__func__, "WEBSERVER INFO", "REQUEST: %s\n", _stcpWI->request);
    /* GET ENDPOINT */
    while (_stcpWI->rcv_header[idx_char] != ' ' && _stcpWI->rcv_header[idx_char] != 0x00){
        if (buffer_size < content_size){
            buffer_size = buffer_size + 8;
            _stcpWI->rcv_endpoint = (char *) realloc(_stcpWI->rcv_endpoint, buffer_size * sizeof(char));
        }
        _stcpWI->rcv_endpoint[idx_content] = _stcpWI->rcv_header[idx_char];
        _stcpWI->rcv_endpoint[idx_content + 1] = 0x00;
        idx_char++;
        content_size++;
        idx_content++;
    }
    stcp_debug(__func__, "WEBSERVER INFO", "ENDPOINT: %s\n", _stcpWI->rcv_endpoint);
    /* GET CONTENT TYPE */
    if (strstr(_stcpWI->rcv_header, "Content-Type:") != NULL){
        if (stcp_http_webserver_header_get(
         (unsigned char *) _stcpWI->rcv_header,
         (unsigned char *) "Content-Type:",
         (unsigned char **) &(_stcpWI->rcv_content_type),
         '\r') != 0){
            strcpy(_stcpWI->rcv_content_type, "failed");
        }
    }
    else {
        strcpy(_stcpWI->rcv_content_type, "(null)");
    }
    stcp_debug(__func__, "WEBSERVER INFO", "CONTENT TYPE: %s\n", _stcpWI->rcv_content_type);
    /* GET CONNECTION TYPE */
    if (strstr(_stcpWI->rcv_header, "Connection:") != NULL){
        if (stcp_http_webserver_header_get(
         (unsigned char *) _stcpWI->rcv_header,
         (unsigned char *) "Connection:",
         (unsigned char **) &(_stcpWI->rcv_connection_type),
         '\r') != 0){
            strcpy(_stcpWI->rcv_connection_type, "closed");
        }
    }
    else {
        strcpy(_stcpWI->rcv_content_type, "closed");
    }
    stcp_debug(__func__, "WEBSERVER INFO", "CONNECTION: %s\n", _stcpWI->rcv_connection_type);
    /* GET ACCEPTION TYPE */
    if (strstr(_stcpWI->rcv_header, "Accept:") != NULL){
        if (stcp_http_webserver_header_get(
         (unsigned char *) _stcpWI->rcv_header,
         (unsigned char *) "Accept:",
         (unsigned char **) &(_stcpWI->rcv_acception_type),
         '\r') != 0){
            strcpy(_stcpWI->rcv_acception_type, "failed");
        }
    }
    else {
        strcpy(_stcpWI->rcv_acception_type, "(null)");
    }
    stcp_debug(__func__, "WEBSERVER INFO", "ACCEPT: %s\n", _stcpWI->rcv_acception_type);
    /* GET AUTH */
    if (strstr(_stcpWI->rcv_header, "Authentication:") != NULL){
        if (stcp_http_webserver_header_get(
         (unsigned char *) _stcpWI->rcv_header,
         (unsigned char *) "Authentication:",
         (unsigned char **) &(_stcpWI->rcv_auth),
         '\r') != 0){
            strcpy(_stcpWI->rcv_auth, "failed");
        }
    }
    else if (strstr(_stcpWI->rcv_header, "Authorization:") != NULL){
        if (stcp_http_webserver_header_get(
         (unsigned char *) _stcpWI->rcv_header,
         (unsigned char *) "Authorization:",
         (unsigned char **) &(_stcpWI->rcv_auth),
         '\r') != 0){
            strcpy(_stcpWI->rcv_auth, "failed");
        }
    }
    else {
        strcpy(_stcpWI->rcv_auth, "(null)");
    }
    stcp_debug(__func__, "WEBSERVER INFO", "AUTH: %s\n", _stcpWI->rcv_auth);
    /* GET COOKIE */
    if (strstr(_stcpWI->rcv_header, "Cookie:") != NULL){
        if (stcp_http_webserver_header_get(
         (unsigned char *) _stcpWI->rcv_header,
         (unsigned char *) "Cookie:",
         (unsigned char **) &(_stcpWI->rcv_cookies),
         '\r') != 0){
            strcpy(_stcpWI->rcv_cookies, "failed");
        }
    }
    else {
        strcpy(_stcpWI->rcv_cookies, "(null)");
    }
    stcp_debug(__func__, "WEBSERVER INFO", "COOKIE: %s\n", _stcpWI->rcv_cookies);
    /* GET CONTENT LENTH */
    _stcpWI->content_length = (uint32_t) stcp_get_content_length(_stcpWI->rcv_header);

    stcp_debug(__func__, "WEBSERVER INFO", "CONTENT LENGTH: %i\n", _stcpWI->content_length);
}

int8_t stcp_http_webserver_generate_header(stcpWInfo *_stcpWI, char *_response_header, char *_content_type, char *_acception_type, uint16_t _content_length){
    time_t stcp_time_access = 0;
    struct tm *tm_access = NULL;
    char *header_tmp = NULL;
    time(&stcp_time_access);
    tm_access = gmtime(&stcp_time_access);
    char day_id[4];
    char month_id[4];
    memset(day_id, 0x00, sizeof(day_id));
    memset(month_id, 0x00, sizeof(month_id));
    switch (tm_access->tm_wday){
        case 0:
            strcpy(day_id, "Sun");
        break;
        case 1:
            strcpy(day_id, "Mon");
        break;
        case 2:
            strcpy(day_id, "Tue");
        break;
        case 3:
            strcpy(day_id, "Wed");
        break;
        case 4:
            strcpy(day_id, "Thu");
        break;
        case 5:
            strcpy(day_id, "Fry");
        break;
        case 6:
            strcpy(day_id, "Sat");
        break;
    }
    switch (tm_access->tm_mon){
        case 0:
            strcpy(month_id, "Jan");
        break;
        case 1:
            strcpy(month_id, "Feb");
        break;
        case 2:
            strcpy(month_id, "Mar");
        break;
        case 3:
            strcpy(month_id, "Apr");
        break;
        case 4:
            strcpy(month_id, "May");
        break;
        case 5:
            strcpy(month_id, "Jun");
        break;
        case 6:
            strcpy(month_id, "Jul");
        break;
        case 7:
            strcpy(month_id, "Aug");
        break;
        case 8:
            strcpy(month_id, "Sep");
        break;
        case 9:
            strcpy(month_id, "Oct");
        break;
        case 10:
            strcpy(month_id, "Nov");
        break;
        case 11:
            strcpy(month_id, "Dec");
        break;
    }
    if (_content_length > 0){
        header_tmp = (char *) stcp_http_content_generator(1024,
         "HTTP/1.1 %s\r\n"
         "Date: %s, %02d %s %04d %02d:%02d:%02d GMT\r\n"
         "Content-Type: %s\r\n"
         "Content-Length: %i\r\n"
         "Server: stcp-webservice\r\n"
         "Accept-Ranges: none\r\n"
         "Accept: %s\r\n"
         "Vary: Accept-Encoding\r\n"
         "Connection: close\r\n"
         "\r\n",
         _response_header,
         day_id, tm_access->tm_mday, month_id, (tm_access->tm_year + 1900), tm_access->tm_hour, tm_access->tm_min, tm_access->tm_sec,
         _content_type,
         _content_length,
         _acception_type
        );
    }
    else {
        header_tmp = (char *) stcp_http_content_generator(1024,
         "HTTP/1.1 %s\r\n"
         "Date: %s, %02d %s %04d %02d:%02d:%02d GMT\r\n"
         "Content-Type: %s\r\n"
         "Server: stcp-webservice\r\n"
         "Accept-Ranges: none\r\n"
         "Accept: %s\r\n"
         "Vary: Accept-Encoding\r\n"
         "Connection: close\r\n"
         "\r\n",
         _response_header,
         day_id, tm_access->tm_mday, month_id, (tm_access->tm_year + 1900), tm_access->tm_hour, tm_access->tm_min, tm_access->tm_sec,
         _content_type,
         _acception_type
        );
    }

    if (header_tmp == NULL){
        stcp_debug(__func__, "ERROR", "failed to generate webserver header\n");
        return -1;
    }

    _stcpWI->server_header = (char *) realloc(_stcpWI->server_header, (strlen(header_tmp) + 1)*sizeof(char));
    strcpy(_stcpWI->server_header, header_tmp);

    free(header_tmp);
    header_tmp = NULL;

    return 0;
}

int8_t stcp_http_webserver_add_negative_code_response(stcpWList *_stcpWList, stcp_webserver_negative_code _code_param, char *_response_content){
    SHLinkCustomData _data;
    char data_key[4];
    if (_code_param == STCP_401_UNAUTHOIZED){
        strcpy(data_key, "401");
    }
    else if (_code_param == STCP_404_NOT_FOUND){
        strcpy(data_key, "404");
    }
    else if (_code_param == STCP_405_METHOD_NOT_ALLOWED){
        strcpy(data_key, "405");
    }
    else {
        stcp_debug(__func__, "ERROR", "invalid parameters\n");
        return -1;
    }
    if(shilink_fill_custom_data(&_data, data_key, _response_content, SL_TEXT) != 0){
        stcp_debug(__func__, "ERROR", "failed to add response (1)\n");
        return -2;
    }
    if (shilink_append(_stcpWList, _data) != 0){
        stcp_debug(__func__, "ERROR", "failed to add response (2)\n");
        shilink_free_custom_data(&_data);
        return -2;
    }
    return 0;
}

int8_t stcp_http_webserver_add_response(stcpWList *_stcpWList, char *_end_point, char *_response_content, char *_request_method){
    SHLinkCustomData _data;
    char data_key[strlen(_end_point) + strlen(_request_method) + 1];
    memset(data_key, 0x00, sizeof(data_key));
    sprintf(data_key, "%s%s", _request_method, _end_point);
    if(shilink_fill_custom_data(&_data, data_key, _response_content, SL_TEXT) != 0){
        stcp_debug(__func__, "ERROR", "failed to add response (1)\n");
        return -1;
    }
    if (shilink_append(_stcpWList, _data) != 0){
        stcp_debug(__func__, "ERROR", "failed to add response (2)\n");
        shilink_free_custom_data(&_data);
        return -1;
    }
    return 0;
}

int8_t stcp_http_webserver_add_response_file(stcpWList *_stcpWList, char *_end_point, char *_response_file, char *_request_method){
    SHLinkCustomData _data;
    char data_key[strlen(_end_point) + strlen(_request_method) + 1];
    char data_value[strlen(_response_file) + 11];
    memset(data_key, 0x00, sizeof(data_key));
    memset(data_value, 0x00, sizeof(data_value));
    sprintf(data_key, "%s%s", _request_method, _end_point);
    sprintf(data_value, "open_file:%s", _response_file);
    if(shilink_fill_custom_data(&_data, data_key, data_value, SL_TEXT) != 0){
        stcp_debug(__func__, "ERROR", "failed to add response (1)\n");
        return -1;
    }
    if (shilink_append(_stcpWList, _data) != 0){
        stcp_debug(__func__, "ERROR", "failed to add response (2)\n");
        shilink_free_custom_data(&_data);
        return -1;
    }
    return 0;
}

int8_t stcp_http_webserver_add_response_function(stcpWList *_stcpWList, char *_end_point, char *_response_function, char *_request_method){
    SHLinkCustomData _data;
    char data_key[strlen(_end_point) + strlen(_request_method) + 1];
    char data_value[strlen(_response_function) + 11];
    memset(data_key, 0x00, sizeof(data_key));
    memset(data_value, 0x00, sizeof(data_value));
    sprintf(data_key, "%s%s", _request_method, _end_point);
    sprintf(data_value, "call_func:%s", _response_function);
    if(shilink_fill_custom_data(&_data, data_key, data_value, SL_TEXT) != 0){
        stcp_debug(__func__, "ERROR", "failed to add response (1)\n");
        return -1;
    }
    if (shilink_append(_stcpWList, _data) != 0){
        stcp_debug(__func__, "ERROR", "failed to add response (2)\n");
        shilink_free_custom_data(&_data);
        return -1;
    }
    return 0;
}

char *stcp_http_webserver_select_response(stcpWInfo *_stcpWI, stcpWList _stcpWList, char *_respons_code){
    SHLinkCustomData _data;
    uint16_t size_end_point = 0;
    if (strstr(_stcpWI->rcv_endpoint, "?") != NULL){
        do {
            size_end_point++;
        } while (_stcpWI->rcv_endpoint[size_end_point] != '?');
        char data_url[(strlen(_stcpWI->rcv_endpoint) + 2) - size_end_point];
        memset(data_url, 0x00, sizeof(data_url));
        uint16_t idx_url_data = 0;
        do {
            data_url[idx_url_data] = _stcpWI->rcv_endpoint[idx_url_data + size_end_point + 1];
            idx_url_data++;
        } while (_stcpWI->rcv_endpoint[idx_url_data + size_end_point + 1] != 0x00);
        _stcpWI->auth_end_point = (char *) realloc(_stcpWI->auth_end_point, (strlen(data_url) + 1)*sizeof(char));
        strcpy(_stcpWI->auth_end_point, data_url);
        size_end_point+=1;
    }
    else {
        size_end_point = strlen(_stcpWI->rcv_endpoint) + 1;
    }

    char data_key[strlen(_stcpWI->request) + size_end_point];
    char end_point[size_end_point];
    memset(data_key, 0x00, sizeof(data_key));
    memset(end_point, 0x00, sizeof(end_point));

    memcpy(end_point, _stcpWI->rcv_endpoint, (size_end_point - 1));

    printf("end_point: %s\n", end_point);
    printf("end_point_data_url:%s\n", _stcpWI->auth_end_point);
    sprintf(data_key, "%s%s", _stcpWI->request, end_point);
    if (shilink_search_data_by_position(_stcpWList, data_key, 0, &_data) != 0){
        if (strcmp("GET", _stcpWI->request) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            sprintf(data_key, "GET%s", _stcpWI->rcv_endpoint);
            if (shilink_search_data_by_position(_stcpWList, data_key, 0, &_data) == 0){
                goto next405;
            }
        }
        if (strcmp("POST", _stcpWI->request) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            sprintf(data_key, "POST%s", _stcpWI->rcv_endpoint);
            if (shilink_search_data_by_position(_stcpWList, data_key, 0, &_data) == 0){
                goto next405;
            }
        }
        if (strcmp("PUT", _stcpWI->request) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            sprintf(data_key, "PUT%s", _stcpWI->rcv_endpoint);
            if (shilink_search_data_by_position(_stcpWList, data_key, 0, &_data) == 0){
                goto next405;
            }
        }
        if (strcmp("HEAD", _stcpWI->request) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            sprintf(data_key, "HEAD%s", _stcpWI->rcv_endpoint);
            if (shilink_search_data_by_position(_stcpWList, data_key, 0, &_data) == 0){
                goto next405;
            }
        }
        if (strcmp("DELETE", _stcpWI->request) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            sprintf(data_key, "DELETE%s", _stcpWI->rcv_endpoint);
            if (shilink_search_data_by_position(_stcpWList, data_key, 0, &_data) == 0){
                goto next405;
            }
        }
        if (strcmp("PATCH", _stcpWI->request) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            sprintf(data_key, "PATCH%s", _stcpWI->rcv_endpoint);
            if (shilink_search_data_by_position(_stcpWList, data_key, 0, &_data) == 0){
                goto next405;
            }
        }
        if (strcmp("OPTIONS", _stcpWI->request) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            sprintf(data_key, "OPTIONS%s", _stcpWI->rcv_endpoint);
            if (shilink_search_data_by_position(_stcpWList, data_key, 0, &_data) == 0){
                goto next405;
            }
        }
        strcpy(_respons_code, "404 Not Found");
        if (shilink_search_data_by_position(_stcpWList, "404", 0, &_data) != 0){
            return NULL;
        }
        return _data.sl_value;
        
        next405 :
            strcpy(_respons_code, "405 Method Not Allowed");
            if (shilink_search_data_by_position(_stcpWList, "405", 0, &_data) != 0){
                return NULL;
            }
            return _data.sl_value;
    }
    strcpy(_respons_code, "200 OK");
    printf("selected response: %s\n", _data.sl_value);
    return _data.sl_value;
}

int8_t stcp_http_webserver_set_content_type(stcpWHead *_stcpWH, char *_content_type){
    _stcpWH->content_type = (char *) realloc(_stcpWH->content_type, (strlen(_content_type) + 1)*sizeof(char));
    strcpy(_stcpWH->content_type, _content_type);
    return 0;
}

int8_t stcp_http_webserver_set_accept(stcpWHead *_stcpWH, char *_accept){
    _stcpWH->accept_type = (char *) realloc(_stcpWH->accept_type, (strlen(_accept) + 1)*sizeof(char));
    strcpy(_stcpWH->accept_type, _accept);
    return 0;
}

int8_t stcp_http_webserver_send_file(stcpSock _init_data, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, char *_response_code, char *_file_name){
    stcp_debug(__func__, "INFO", "file name: %s\n", _file_name);

    FILE *stcp_file = NULL;
    uint8_t try_times = 3;

    do{
    	stcp_file = fopen(_file_name, "r");
        try_times--;
    } while (stcp_file == NULL && try_times > 0);

    if (stcp_file == NULL){
        stcp_debug(__func__, "ERROR", "failed to open \"%s\"\n", _file_name);
        if (stcp_http_webserver_generate_header(
         _stcpWI,
         _response_code,
         _stcpWH->content_type,
         _stcpWH->accept_type,
         11) != 0
        ){
            return -1;
        }
        char *buffer_info;

        buffer_info = stcp_http_content_generator(
         (strlen(_stcpWI->server_header) + 13),
         "%snot found!\n", _stcpWI->server_header
        );
        if (buffer_info == NULL){
            stcp_debug(__func__, "ERROR", "failed to generate webserver content\n");
            return -1;
        }
        if (!_stcpWI->comm_protocol){
            stcp_send_data(_init_data, (unsigned char *) buffer_info, strlen(buffer_info));
        }
        else{
            #ifdef __STCP_SSL__
                stcp_ssl_send_data(_init_data, (unsigned char *) buffer_info, strlen(buffer_info));
            #endif
        }
        free(buffer_info);
        buffer_info = NULL;
        return -2;
    }

    uint32_t content_size = 0;
    fseek(stcp_file, 0L, SEEK_END);
    content_size = (uint32_t) ftell(stcp_file);

    fseek(stcp_file, 0L, SEEK_SET);

    char content_type_file[strlen(_stcpWH->content_type) + 1];
    if (strstr(_file_name, ".css") != NULL){
        strcpy(content_type_file, "text/css");
    }
    else if (strstr(_file_name, ".html") != NULL){
        strcpy(content_type_file, "text/html");
    }
    else if (strstr(_file_name, ".mp4") != NULL){
        strcpy(content_type_file, "video/mp4");
    }
    else {
        strcpy(content_type_file, _stcpWH->content_type);
    }

    if (stcp_http_webserver_generate_header(
     _stcpWI,
     _response_code,
     content_type_file,
     _stcpWH->accept_type,
     content_size) != 0
    ){
        fclose(stcp_file);
        return -1;
    }

    unsigned char *file_content = NULL;
    file_content = (unsigned char *) malloc(stcp_setup_data.stcp_size_per_send * sizeof(char));
    if (file_content == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate memory for file_content\n");
        fclose(stcp_file);
        return -3;
    }

    if (!_stcpWI->comm_protocol){
        stcp_send_data(_init_data, (unsigned char *) _stcpWI->server_header, strlen(_stcpWI->server_header));
    }
    else {
        #ifdef __STCP_SSL__
            stcp_ssl_send_data(_init_data, (unsigned char *) _stcpWI->server_header, strlen(_stcpWI->server_header));
        #endif
    }

    uint32_t size_recv = 0;
    int8_t bytes = 0;
    uint32_t total_size = 0;
    unsigned char buff[2];
    while((bytes = fread((unsigned char *) buff, 1, 1, stcp_file) >= 0)){
		total_size = total_size + 1;
        file_content[size_recv] = buff[0];
        size_recv = size_recv + 1;
        if (size_recv == (stcp_setup_data.stcp_size_per_send * sizeof(char)) - 1 || bytes == 0){
            if (!_stcpWI->comm_protocol){
                if (stcp_send_data(_init_data, file_content, size_recv) <= 0){
                    break;
                }
            }
            else {
                #ifdef __STCP_SSL__
                    if (stcp_ssl_send_data(_init_data, file_content, size_recv) <= 0){
                        break;
                    }
                #else
                    break;
                #endif
            }
            memset(file_content, 0x00, (stcp_setup_data.stcp_size_per_send * sizeof(char)));
            if (size_recv == 0){
                break;
            }
            size_recv = 0;
        }
        if (total_size == content_size){
            if (size_recv > 0){
                if (!_stcpWI->comm_protocol){
                    if (stcp_send_data(_init_data, file_content, size_recv) <= 0){
                        break;
                    }
                }
                else {
                    #ifdef __STCP_SSL__
                        if (stcp_ssl_send_data(_init_data, file_content, size_recv) <= 0){
                            break;
                        }
                    #else
                        break
                    #endif
                }
                memset(file_content, 0x00, (stcp_setup_data.stcp_size_per_recv * sizeof(char)));
                if (size_recv == 0){
                    break;
                }
                size_recv = 0;
            }
            break;
        }
	}
    free(file_content);
    file_content = NULL;
    fclose(stcp_file);
    return 0;
}

int8_t stcp_http_webserver(char *ADDRESS, uint16_t PORT, uint16_t MAX_CLIENT, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList _stcpWList){
    if (stcp_webserver_init_state == 0){
        stcp_debug(__func__, "ERROR", "web server not ready\n");
        return -1;
    }

    /* check address & protocol*/
    /* 0 for http and 1 for https */
    _stcpWI->comm_protocol = 0;

    char *used_address = NULL;
    used_address = (char *) malloc((strlen(ADDRESS) + 1) * sizeof(char));
    if (used_address == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate address memory\n");
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        return -1;
    }

    memset(used_address, 0x00, (strlen(ADDRESS) + 1) * sizeof(char));
    if (strstr(ADDRESS, "http://") != NULL){
        memcpy(used_address, ADDRESS + 7, strlen(ADDRESS) - 7);
    }
    else if (strstr(ADDRESS, "https://") != NULL){
        memcpy(used_address, ADDRESS + 8, strlen(ADDRESS) - 8);
        _stcpWI->comm_protocol = 1;
        #ifndef __STCP_SSL__
            stcp_debug(__func__, "ERROR", "please define __STCP_SSL__ first\n");
            stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
            return -1;
        #endif
    }
    else {
        memcpy(used_address, ADDRESS, strlen(ADDRESS));
    }

    if (used_address[strlen(used_address) - 1] == '/'){
        used_address[strlen(used_address) - 1] = 0x00;
    }
    
    #ifdef __STCP_SSL__
        SSL_CTX *ssl_ctx = NULL;
    #endif

    stcpSock init_data;
    fd_set readfds;

    char *buffer = NULL;
    uint32_t buffer_size = stcp_setup_data.stcp_size_per_recv;
    buffer = (char *) malloc(buffer_size * sizeof(char));
    if (buffer == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate memory\n");
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        free(used_address);
        used_address = NULL;
        init_data.socket_f = -1;
        return -1;
    }
    socklen_t len;
    struct sockaddr_in servaddr, cli;
    init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
    if (init_data.socket_f == -1) {
        stcp_debug(__func__, "CRITICAL", "socket creation failed...\n");
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        free(used_address);
        free(buffer);
        used_address = NULL;
        buffer = NULL;
        return -1;
    }
    stcp_debug(__func__, "INFO", "Socket successfully created : %d\n", init_data.socket_f);
    memset(&servaddr, 0x00, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    if(stcp_check_ip(used_address) != 0){
        struct hostent *host;
        host = gethostbyname(used_address);
        if (host != NULL){
            servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
        }
        else {
            stcp_debug(__func__, "ERROR", "failed to get host by name\n", used_address);
            close(init_data.socket_f);
            init_data.socket_f = -1;
            stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
            free(used_address);
            free(buffer);
            used_address = NULL;
            buffer = NULL;
            return -2;
        }
    }
    else {
        servaddr.sin_addr.s_addr = inet_addr(used_address);
    }

    free(used_address);
    used_address = NULL;

    const int optVal = 1;
    const socklen_t optLen = sizeof(optVal);
    setsockopt(init_data.socket_f, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen);
            
    if ((bind(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        stcp_debug(__func__, "CRITICAL", "socket bind failed...\n");
        if (stcp_setup_data.stcp_retry_mode == 1) stcp_debug(__func__, "INFO", "trying to create a socket...\n");
        close(init_data.socket_f);
        init_data.socket_f = 0;
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        free(buffer);
        buffer = NULL;
        return -2;
    }
    stcp_debug(__func__, "INFO", "Socket successfully binded..\n");
    if ((listen(init_data.socket_f, 5)) != 0) { 
        stcp_debug(__func__, "CRITICAL", "Listen failed...\n");
        close(init_data.socket_f);
        init_data.socket_f = 0;
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        free(buffer);
        buffer = NULL;
        return -2;
    }
    if (!_stcpWI->comm_protocol){
        stcp_debug(__func__, "WEBSERVER INFO", "Server listening..\n"); 
    }
    else {
        stcp_debug(__func__, "WEBSERVER INFO", "Server https listening..\n");
    }
    len = sizeof(cli);

    int client_fd[MAX_CLIENT];
    uint16_t keep_alive_cnt[MAX_CLIENT];
    struct timeval tv_timer;

    memset(client_fd, 0x00, sizeof(client_fd));
    memset(keep_alive_cnt, 0x00, sizeof(keep_alive_cnt));
    memset(buffer, 0x00, buffer_size*sizeof(char));

    int32_t stcp_bytes = 0;
    uint32_t stcp_size = 8;
    uint32_t idx_chr = 0;
    uint16_t max_sd = 0;
    uint16_t idx_client = 0;
    int16_t activity = 0;
    int8_t retval;
    int8_t proc_state = STCP_PROCESS_GET_HEADER;
    stcp_server_state = STCP_SERVER_RUNING;

    char response_code[32];

    while (stcp_server_state == STCP_SERVER_RUNING){
        FD_ZERO(&readfds);   
        FD_SET(init_data.socket_f, &readfds);   
        max_sd = (uint16_t) init_data.socket_f;   
             
        /* add child sockets to set */
        for (idx_client = 0 ; idx_client < MAX_CLIENT ; idx_client++){     
            if(client_fd[idx_client] > 0){
                FD_SET(client_fd[idx_client] , &readfds);
            }
            if(client_fd[idx_client] > max_sd){
                max_sd = client_fd[idx_client];   
            }
        }

        if (stcp_setup_data.stcp_keepalive_sec > 0 || stcp_setup_data.stcp_keepalive_millisec > 0){
            tv_timer.tv_sec = stcp_setup_data.stcp_keepalive_sec;
            tv_timer.tv_usec = stcp_setup_data.stcp_keepalive_millisec * 1000;
            activity = select(max_sd + 1 , &readfds , NULL , NULL , &tv_timer);
        }
        else {
            activity = select(max_sd + 1 , &readfds , NULL , NULL , NULL);
        }
        if ((activity < 0) && (errno!=EINTR))   
        {
            stcp_debug(__func__, "ERROR", "select error\n");
        }

        if (FD_ISSET(init_data.socket_f, &readfds) && stcp_server_state == STCP_SERVER_RUNING)   
        {   
            tv_timer.tv_sec = stcp_setup_data.stcp_timeout_sec;
            tv_timer.tv_usec = stcp_setup_data.stcp_timeout_millisec * 1000;
            if ((init_data.connection_f = accept(init_data.socket_f, (SA*)&cli, &len))<0){  
                stcp_debug(__func__, "INFO", "accept failed\n");
            }
            else {
                strcpy(_stcpWI->ipaddr, inet_ntoa(cli.sin_addr));
                for (idx_client = 0; idx_client < MAX_CLIENT; idx_client++){
                    if(client_fd[idx_client] == 0 ){
                        client_fd[idx_client] = init_data.connection_f;
                        stcp_debug(__func__, "WEBSERVER INFO", "new connection (%d:%d) %s:%d\n" ,
                         init_data.connection_f, idx_client, _stcpWI->ipaddr, ntohs(cli.sin_port)
                        );
                        break;   
                    }   
                }
            }
        }
        else if (stcp_server_state == STCP_SERVER_RUNING &&
         (stcp_setup_data.stcp_keepalive_sec > 0 || stcp_setup_data.stcp_keepalive_millisec > 0)
        ){
            for (idx_client = 0; idx_client<MAX_CLIENT; idx_client++){
                if (keep_alive_cnt[idx_client] > 0 && client_fd[idx_client] > 0){
                    gettimeofday(&tv_timer, NULL);
                    if ((keep_alive_cnt[idx_client] +
                      (stcp_setup_data.stcp_keepalive_sec*1000) +
                      stcp_setup_data.stcp_keepalive_millisec
                     ) <=
                     ((tv_timer.tv_sec%60)*1000 + (tv_timer.tv_usec/1000))
                    ){
                        keep_alive_cnt[idx_client] = 0;
                        if (_stcpWI->comm_protocol){
                            #ifdef __STCP_SSL__
                                SSL_free(init_data.ssl_connection_f);
                                init_data.ssl_connection_f = NULL;
                            #endif
                        }
                        close(client_fd[idx_client]);
                        client_fd[idx_client] = 0;
                        stcp_debug(__func__, "WEBSERVER INFO", "one client connection closed (%i)\n", idx_client);
                    }
                }
            }
        }
        for (idx_client = 0; idx_client < MAX_CLIENT && stcp_server_state == STCP_SERVER_RUNING; idx_client++){
            init_data.connection_f = client_fd[idx_client];
            if (FD_ISSET(init_data.connection_f , &readfds))   
            {
                stcp_bytes = 0;
                stcp_size = 8;
                idx_chr = 0;
                stcp_http_webserver_bzero(_stcpWI, _stcpWH);
                proc_state = STCP_PROCESS_GET_HEADER;
                #ifdef __STCP_SSL__
                    if (_stcpWI->comm_protocol){
                        ssl_ctx = NULL;
                        #ifdef SSLv23_server_method
                            ssl_ctx = SSL_CTX_new (SSLv23_server_method ());
                        #else
                            ssl_ctx = SSL_CTX_new (TLSv1_2_server_method ());
                        #endif
                        if (ssl_ctx == NULL){
                            stcp_debug(__func__, "WARNING", "unable to create new SSL context structure\n");
                        }
                        init_data.ssl_connection_f = SSL_new(ssl_ctx);
                        SSL_set_fd(init_data.ssl_connection_f, init_data.connection_f);
                        if (SSL_accept(init_data.ssl_connection_f) == -1){
                            stcp_debug(__func__, "WARNING", "ssl accept failed\n");
                            goto close_client;
                            SSL_CTX_free(ssl_ctx);
                            ssl_ctx = NULL;
                        }
                        SSL_get_peer_certificate(init_data.ssl_connection_f);
                        SSL_CTX_free(ssl_ctx);
                        ssl_ctx = NULL;
                    }
                #endif
                while(stcp_server_state == STCP_SERVER_RUNING){
                    if (proc_state == STCP_PROCESS_GET_HEADER){
                        if (!_stcpWI->comm_protocol){
                            stcp_bytes = stcp_recv_data(init_data, (unsigned char *) buffer, buffer_size);
                        }
                        else {
                            #ifdef __STCP_SSL__
                                stcp_bytes = stcp_ssl_recv_data(init_data, (unsigned char *) buffer, buffer_size);
                            #else
                                goto close_client;
                            #endif
                        }
                        if (stcp_bytes <= 0){
                            if(strstr(_stcpWI->rcv_header, "HTTP") != NULL || stcp_bytes < 0){
                                stcp_debug(__func__, "WEBSERVER INFO", "Lost Connection..\n");
                                goto close_client;
                            }
                            else if (keep_alive_cnt[idx_client] > 0){
                                gettimeofday(&tv_timer, NULL);
                                if ((keep_alive_cnt[idx_client] +
                                  (stcp_setup_data.stcp_keepalive_sec*1000) +
                                  stcp_setup_data.stcp_keepalive_millisec
                                 ) <=
                                 ((tv_timer.tv_sec%60)*1000 + (tv_timer.tv_usec/1000))
                                ){
                                    keep_alive_cnt[idx_client] = 0;
                                    goto close_client;
                                }
                            }
                            goto stcp_func;
                        }
                        else {
                            while (stcp_size < (idx_chr + stcp_bytes) + 2){
                                stcp_size = stcp_size + 8;
                                if (stcp_size >= (idx_chr + stcp_bytes) + 2){
                                    _stcpWI->rcv_header = (char *) realloc(_stcpWI->rcv_header, (stcp_size + 1)*sizeof(char));
                                }
                            }
                            memcpy(_stcpWI->rcv_header + idx_chr, buffer, stcp_bytes);
                            if(strstr(_stcpWI->rcv_header, "HTTP") == NULL){
                                if(_stcpWI->rcv_header[idx_chr + stcp_bytes - 1] == '\n'){
                                    stcp_debug(__func__, "WEBSERVER INFO", "goto stcp origin function\n");
                                    goto stcp_func;
                                }
                                idx_chr = stcp_bytes - 1;
                            }
                            else {
                                if (!idx_chr){
                                    idx_chr = 4;
                                }
                                do {
                                    if(_stcpWI->rcv_header[idx_chr - 1] == '\n' && _stcpWI->rcv_header[idx_chr - 2] == '\r' &&
                                     _stcpWI->rcv_header[idx_chr - 3] == '\n' && _stcpWI->rcv_header[idx_chr - 4] == '\r'
                                    ){
                                        if (stcp_bytes > 0){
                                            stcp_size = stcp_bytes - 3;
                                            _stcpWI->rcv_content = (char *) realloc(_stcpWI->rcv_content, stcp_size*sizeof(char));
                                            memset(_stcpWI->rcv_content, 0x00, stcp_size);
                                            memcpy(_stcpWI->rcv_content, _stcpWI->rcv_header + idx_chr, (stcp_bytes - 4));
                                            _stcpWI->rcv_header[idx_chr] = 0x00;
                                            _stcpWI->rcv_header = (char *) realloc(_stcpWI->rcv_header, (idx_chr + 1)*sizeof(char));
                                        }
                                        else {
                                            _stcpWI->rcv_header[idx_chr] = 0x00;
                                        }
                                        stcp_http_webserver_header_parser(_stcpWI);
                                        proc_state = STCP_PROCESS_GET_CONTENT;
                                        idx_chr = stcp_bytes - 4;
                                        break;
                                    }
                                    idx_chr++;
                                    stcp_bytes--;
                                } while (stcp_bytes >= 0);
                            }
                            if ((_stcpWI->content_length == 0 || (idx_chr + 1) >= _stcpWI->content_length) &&
                             proc_state == STCP_PROCESS_GET_CONTENT
                            ){
                                break;
                            }
                            else {
                                _stcpWI->rcv_header[idx_chr + 1] = 0x00;
                            }
                        }
                    }
                    else{
                        if (!_stcpWI->comm_protocol){
                            stcp_bytes = stcp_recv_data(init_data, (unsigned char *) buffer, _stcpWI->content_length);
                        }
                        else {
                            #ifdef __STCP_SSL__
                                stcp_bytes = stcp_ssl_recv_data(init_data, (unsigned char *) buffer, _stcpWI->content_length);
                            #else
                                goto close_client;
                            #endif
                        }
                        if (stcp_bytes <= 0){
                            stcp_debug(__func__, "WEBSERVER INFO", "Lost Connection..\n");
                            goto close_client;
                        }
                        else {
                            while (stcp_size < (idx_chr + stcp_bytes) + 2){
                                stcp_size = stcp_size + 8;
                                if (stcp_size >= idx_chr + 2){
                                    _stcpWI->rcv_content = (char *) realloc(_stcpWI->rcv_content, stcp_size*sizeof(char));
                                }
                            }
                            memcpy(_stcpWI->rcv_content + idx_chr, buffer, stcp_bytes);
                            idx_chr = idx_chr + stcp_bytes;
                            _stcpWI->rcv_content[idx_chr] = 0x00;
                        }
                        if (_stcpWI->content_length > 0 && (idx_chr) >= _stcpWI->content_length){
                            break;
                        }
                    }
                }
                if (strlen(_stcpWI->rcv_content) > 0){
                    printf("Content (%lu):\n%s\n", strlen(_stcpWI->rcv_content), _stcpWI->rcv_content);
                }
                
                char *response_content = NULL;
                char *buffer_info = NULL;
                memset(response_code, 0x00, sizeof(response_code));
                response_content = stcp_http_webserver_select_response(_stcpWI, _stcpWList, response_code);
                /* user handling start here */
                if (response_content == NULL) {
                    if (stcp_http_webserver_generate_header(
                     _stcpWI,
                     response_code,
                     _stcpWH->content_type,
                     _stcpWH->accept_type,
                     0) != 0
                    ){
                        goto close_client;
                    }
                    buffer_info = stcp_http_content_generator(
                     1024,
                     "%scheck header!\r\n", _stcpWI->server_header
                    );
                    if (buffer_info == NULL){
                        stcp_debug(__func__, "ERROR", "failed to generate webserver content\n");
                        goto close_client;
                    }
                    if (!_stcpWI->comm_protocol){
                        stcp_send_data(init_data, (unsigned char *) buffer_info, strlen(buffer_info));
                    }
                    else {
                        #ifdef __STCP_SSL__
                            stcp_ssl_send_data(init_data, (unsigned char *) buffer_info, strlen(buffer_info));
                        #endif
                    }
                    free(buffer_info);
                    buffer_info = NULL;
                    goto stcp_connection_check;
                }
                else if (strncmp(response_content, "open_file:", 10) == 0){
                    char content_file_name[strlen(response_content) - 9];
                    memset(content_file_name, 0x00, sizeof(content_file_name));
                    memcpy(content_file_name, response_content + 10, (strlen(response_content) - 10));
                    if (stcp_http_webserver_send_file(init_data, _stcpWI, _stcpWH, response_code, content_file_name) == -1){
                        goto close_client;
                    }
                    goto stcp_connection_check;
                }
                else if (strncmp(response_content, "call_func:", 10) == 0){
                    char func_name[strlen(response_content) - 9];
                    memset(func_name, 0x00, sizeof(func_name));
                    memcpy(func_name, response_content + 10, (strlen(response_content) - 10));
                    int8_t retval = stcp_http_webserver_function_select(init_data, _stcpWI, _stcpWH, _stcpWList, response_code, func_name);
                    if (retval == -1 || retval == 1){
                        goto stcp_connection_check;
                    }
                    goto stcp_next;
                }
                else {
                    if (stcp_http_webserver_generate_header(
                     _stcpWI,
                     response_code,
                     _stcpWH->content_type,
                     _stcpWH->accept_type,
                     strlen(response_content)) != 0
                    ){
                        goto close_client;
                    }
                    buffer_info = stcp_http_content_generator(
                     (strlen(_stcpWI->server_header) + strlen(response_content) + 2),
                     "%s%s", _stcpWI->server_header, response_content
                    );
                    if (buffer_info == NULL){
                        stcp_debug(__func__, "ERROR", "failed to generate webserver content\n");
                        goto close_client;
                    }
                    if (!_stcpWI->comm_protocol){
                        stcp_send_data(init_data, (unsigned char *) buffer_info, strlen(buffer_info));
                    }
                    else {
                        #ifdef __STCP_SSL__
                            stcp_ssl_send_data(init_data, (unsigned char *) buffer_info, strlen(buffer_info));
                        #endif
                    }
                    free(buffer_info);
                    buffer_info = NULL;
                    goto stcp_connection_check;
                }

                stcp_connection_check:
                    if ((strcmp(_stcpWI->rcv_connection_type, "Keep-Alive") == 0 ||
                     strcmp(_stcpWI->rcv_connection_type, "keep-alive") == 0) &&
                     (stcp_setup_data.stcp_keepalive_sec > 0 ||
                     stcp_setup_data.stcp_keepalive_millisec > 0)
                    ){
                        gettimeofday(&tv_timer, NULL);
                        keep_alive_cnt[idx_client] = (uint16_t) ((tv_timer.tv_sec%60)*1000 + (tv_timer.tv_usec/1000));
                        goto stcp_next;
                    }

                goto close_client;
                
                stcp_func:
                    retval = stcp_http_webserver_function_select(init_data, _stcpWI, _stcpWH, _stcpWList, "STCP RESP", "stcp_select_func");
                    if (retval == -1 || retval == 1){
                        goto close_client;
                    }
                    goto stcp_next;

                /* user handling end here */
                close_client:
                    if (_stcpWI->comm_protocol){
                        #ifdef __STCP_SSL__
                            SSL_free(init_data.ssl_connection_f);
                            init_data.ssl_connection_f = NULL;
                        #endif
                    }
                    close(init_data.connection_f);
                    init_data.connection_f = 0;
                    stcp_debug(__func__, "WEBSERVER INFO", "one client connection closed (%d)\n", idx_client);
                stcp_next:
                    client_fd[idx_client] = init_data.connection_f;
            }
            usleep(100);
        }
    }
    if (!_stcpWI->comm_protocol){
        stcp_close(&init_data);
    }
    else {
        #ifdef __STCP_SSL__
            stcp_ssl_close(&init_data);
        #endif
    }
    stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
    free(buffer);
    buffer = NULL;
    stcp_server_state = STCP_SERVER_STOPED;
    stcp_debug(__func__, "WEBSERVER INFO", "server terminated!\n");
    return 0;
}

void stcp_http_webserver_stop(){
    stcp_server_state = STCP_SERVER_STOP;
    stcp_debug(__func__, "WEBSERVER INFO", "please wait...\n");
    while(stcp_server_state == STCP_SERVER_STOP){
        usleep(10000);
    }
}
#endif

stcpSock stcp_client_init(char *ADDRESS, uint16_t PORT){
    stcpSock init_data;
    int8_t retval = 0;
    struct sockaddr_in servaddr;

    do{
        init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
        if (init_data.socket_f < 0) {
            stcp_debug(__func__, "CRITICAL", "socket creation failed...\n");
            retval = (int8_t) init_data.socket_f;
        }
        else{
            retval = (int8_t) init_data.socket_f;
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

            if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
                struct timeval tv;
                tv.tv_sec = stcp_setup_data.stcp_timeout_sec;
                tv.tv_usec = stcp_setup_data.stcp_timeout_millisec * 1000;
                setsockopt(init_data.socket_f, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
            }

            stcp_debug(__func__, "INFO", "waiting for server...\n");
            if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
                struct timeval tv;
                tv.tv_sec = (time_t) stcp_setup_data.stcp_timeout_sec;
                tv.tv_usec = (suseconds_t) (stcp_setup_data.stcp_timeout_millisec * 1000);
                retval = stcp_connect_with_timeout(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr), &tv);
                if (retval != 0){
                    stcp_debug(__func__, "WARNING", "waiting for server timeout\n");
                    stcp_close(&init_data);
                    return init_data;
                }
            }
            else {
                while (connect(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr)) != 0) {
                    usleep(100000);
                }
            }
            init_data.connection_f = init_data.socket_f;
	        stcp_debug(__func__, "INFO", "connected to the server..\n");
        }
    } while (retval < 0 && stcp_setup_data.stcp_retry_mode == (int8_t) INFINITE_RETRY);
    return init_data;
}

#ifdef __STCP_SSL__
stcpSock stcp_ssl_client_init(char *ADDRESS, uint16_t PORT){
    stcpSock init_data;
    int8_t retval = 0;
    struct sockaddr_in servaddr;

    do{
        init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
        if (init_data.socket_f < 0) {
            stcp_debug(__func__, "CRITICAL", "socket creation failed...\n");
            retval = (int8_t) init_data.socket_f;
        }
        else{
            retval = (int8_t) init_data.socket_f;
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

            if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
                struct timeval tv;
                tv.tv_sec = (time_t) stcp_setup_data.stcp_timeout_sec;
                tv.tv_usec = (suseconds_t) (stcp_setup_data.stcp_timeout_millisec * 1000);
                setsockopt(init_data.socket_f, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
            }

            stcp_debug(__func__, "INFO", "waiting for server...\n");
            if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
                struct timeval tv;
                tv.tv_sec = stcp_setup_data.stcp_timeout_sec;
                tv.tv_usec = stcp_setup_data.stcp_timeout_millisec * 1000;
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

            SSL_CTX *ssl_ctx = NULL;
            #ifdef SSLv23_server_method
                ssl_ctx = SSL_CTX_new (SSLv23_server_method ());
            #else
                ssl_ctx = SSL_CTX_new (TLSv1_2_server_method ());
            #endif

            if (ssl_ctx == NULL){
                stcp_debug(__func__, "WARNING", "unable to create new SSL context structure\n");
            }

            init_data.ssl_connection_f = SSL_new(ssl_ctx);
            SSL_set_fd(init_data.ssl_connection_f, init_data.socket_f);

            int err = SSL_connect(init_data.ssl_connection_f);
            if (err != 1){
                stcp_debug(__func__, "WARNING", "ssl connection failed\n");
            }
            init_data.connection_f = init_data.socket_f;
	        stcp_debug(__func__, "INFO", "connected to the server..\n");
            SSL_CTX_free(ssl_ctx);
        }
    } while (retval < 0 && stcp_setup_data.stcp_retry_mode == (int8_t) INFINITE_RETRY);
    return init_data;
}
#endif

long stcp_get_file_size(char *_file_name){
    stcp_debug(__func__, "INFO", "file name: %s\n", _file_name);

    FILE *stcp_file = NULL;
    uint8_t try_times = 3;

    do{
    	stcp_file = fopen(_file_name, "r");
        try_times--;
    } while (stcp_file == NULL && try_times > 0);

    if (stcp_file == NULL){
        stcp_debug(__func__, "ERROR", "failed to open \"%s\"\n", _file_name);
        return -1;
    }

    long content_size = 0;
    fseek(stcp_file, 0L, SEEK_END);
    content_size = ftell(stcp_file);

    stcp_debug(__func__, "INFO", "file size: %li\n", content_size);

    fclose(stcp_file);
    stcp_file = NULL;
    return content_size;
}

static int8_t stcp_socket_send_file(stcpSock _init_data, char *_file_name, int8_t _socket_type){
    stcp_debug(__func__, "INFO", "file name: %s\n", _file_name);

    FILE *stcp_file = NULL;
    uint8_t try_times = 3;

    do{
    	stcp_file = fopen(_file_name, "r");
        try_times--;
    } while (stcp_file == NULL && try_times > 0);

    if (stcp_file == NULL){
        stcp_debug(__func__, "ERROR", "failed to open \"%s\"\n", _file_name);
        return -1;
    }

    long content_size = 0;
    fseek(stcp_file, 0L, SEEK_END);
    content_size = ftell(stcp_file);

    fseek(stcp_file, 0L, SEEK_SET);

    unsigned char *file_content = NULL;
    file_content = (unsigned char *) malloc(stcp_setup_data.stcp_size_per_send * sizeof(unsigned char));
    if (file_content == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate memory for file_content\n");
        fclose(stcp_file);
        stcp_file = NULL;
        return -2;
    }

    uint32_t size_recv = 0;
    int8_t bytes = 0;
    long total_size = 0;
    unsigned char buff[2];
    while((bytes = (int8_t) fread((unsigned char *) buff, 1, 1, stcp_file) >= 0)){
		total_size = total_size + 1;
        file_content[size_recv] = buff[0];
        size_recv = size_recv + 1;
        if (size_recv == (stcp_setup_data.stcp_size_per_send * sizeof(char)) - 1 || bytes == 0){
            if (_socket_type == STCP_TCP){
                if (stcp_send_data(_init_data, file_content, size_recv) <= 0){
                    break;
                }
            }
            else {
                #ifdef __STCP_SSL__
                    if (stcp_ssl_send_data(_init_data, file_content, size_recv) <= 0){
                        break;
                    }
                #else
                    stcp_debug(__func__, "WARNING", "please enable __STCP_SSL__ on shiki-tcp-ip-tools.h\n");
                    break;
                #endif
            }
            memset(file_content, 0x00, (stcp_setup_data.stcp_size_per_send * sizeof(char)));
            if (size_recv == 0){
                break;
            }
            size_recv = 0;
        }
        if (total_size == content_size){
            if (size_recv > 0){
                if (_socket_type == STCP_TCP){
                    if (stcp_send_data(_init_data, file_content, size_recv) <= 0){
                        break;
                    }
                }
                else {
                    #ifdef __STCP_SSL__
                        if (stcp_ssl_send_data(_init_data, file_content, size_recv) <= 0){
                            break;
                        }
                    #else
                        stcp_debug(__func__, "WARNING", "please enable __STCP_SSL__ on shiki-tcp-ip-tools.h\n");
                        break;
                    #endif
                }
                memset(file_content, 0x00, (stcp_setup_data.stcp_size_per_send * sizeof(char)));
                if (size_recv == 0){
                    break;
                }
                size_recv = 0;
            }
            break;
        }
	}
    free(file_content);
    file_content = NULL;
    fclose(stcp_file);
    stcp_file = NULL;
    return 0;
}

int32_t stcp_send_data(stcpSock _init_data, unsigned char* buff, int32_t size_set){
    int32_t bytes;
    int32_t bytes_aviable = 0;
    uint16_t timeout_cstart = 0;
    uint16_t timeout_cvalue = 0;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    timeout_cstart = (uint16_t) ((tv.tv_sec%60)*1000 + tv.tv_usec/1000);
    if (stcp_setup_data.stcp_timeout_sec == 0 && stcp_setup_data.stcp_timeout_millisec == 0){
        timeout_cvalue = (uint16_t) 3000;
    }
    else {
        timeout_cvalue = (uint16_t) (stcp_setup_data.stcp_timeout_sec*1000 + stcp_setup_data.stcp_timeout_millisec);
    }
    do {
        ioctl(_init_data.connection_f, TIOCOUTQ, &bytes_aviable);
        if (bytes_aviable > 0){
            gettimeofday(&tv, NULL);
            if ((uint16_t)(((tv.tv_sec%60)*1000 + tv.tv_usec/1000) - timeout_cstart) > timeout_cvalue){
                stcp_debug(__func__, "WARNING", "send 0 data. request timeout\n");
                return -1;
            }
        }
    } while (bytes_aviable > 0);
    bytes = (int32_t) write(_init_data.connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to send %d data\n", bytes);
    else if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
        stcp_debug(__func__, "WARNING", "send %d data. request timeout\n", bytes);
    }
    else {
        stcp_debug(__func__, "WARNING", "request timeout\n");
    }
    return bytes;
}

int8_t stcp_send_file(stcpSock _init_data, char *_file_name){
    return stcp_socket_send_file(_init_data, _file_name, STCP_TCP);
}

int32_t stcp_recv_data(stcpSock _init_data, unsigned char* buff, int32_t size_set){
    int32_t bytes;
    bytes = (int32_t) read(_init_data.connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to receive %d data\n", bytes);
    else if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
        stcp_debug(__func__, "WARNING", "receive %d data. request timeout or finished\n", bytes);
    }
    else {
        stcp_debug(__func__, "WARNING", "request timeout\n");
    }
    return bytes;
}

#ifdef __STCP_SSL__
int32_t stcp_ssl_send_data(stcpSock _init_data, unsigned char* buff, int32_t size_set){
    int32_t bytes;
    int32_t bytes_aviable = 0;
    uint16_t timeout_cstart = 0;
    uint16_t timeout_cvalue = 0;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    timeout_cstart = (uint16_t) ((tv.tv_sec%60)*1000 + tv.tv_usec/1000);
    if (stcp_setup_data.stcp_timeout_sec == 0 && stcp_setup_data.stcp_timeout_millisec == 0){
        timeout_cvalue = (uint16_t) 3000;
    }
    else {
        timeout_cvalue = (uint16_t) (stcp_setup_data.stcp_timeout_sec*1000 + stcp_setup_data.stcp_timeout_millisec);
    }
    do {
        ioctl(_init_data.connection_f, TIOCOUTQ, &bytes_aviable);
        if (bytes_aviable > 0){
            gettimeofday(&tv, NULL);
            if ((uint16_t)(((tv.tv_sec%60)*1000 + tv.tv_usec/1000) - timeout_cstart) > timeout_cvalue){
                stcp_debug(__func__, "WARNING", "send 0 data. request timeout\n");
                return -1;
            }
        }
    } while (bytes_aviable > 0);
    bytes = (int32_t) SSL_write(_init_data.ssl_connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to send %d data\n", bytes);
    else if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
        stcp_debug(__func__, "WARNING", "send %d data. request timeout\n", bytes);
    }
    else {
        stcp_debug(__func__, "WARNING", "request timeout\n");
    }
    return bytes;
}

int8_t stcp_ssl_send_file(stcpSock _init_data, char *_file_name){
    return stcp_socket_send_file(_init_data, _file_name, STCP_SSL);
}

int32_t stcp_ssl_recv_data(stcpSock _init_data, unsigned char* buff, int32_t size_set){
    int32_t bytes;
    bytes = (int32_t) SSL_read(_init_data.ssl_connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, "INFO", "success to receive %d data\n", bytes);
    else if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
        stcp_debug(__func__, "WARNING", "receive %d data. request timeout or finished\n", bytes);
    }
    else {
        stcp_debug(__func__, "WARNING", "request timeout\n");
    }
    return bytes;
}
#endif

int8_t stcp_url_parser(char *_url, char *_host, char *_protocol, char *_end_point, uint16_t *_port){
    if (strncmp(_url, "http://", 7) == 0 || strncmp(_url, "https://", 8) == 0){
        char *host = NULL;
        char *end_point = NULL;
        char *buff = NULL;
        host = (char *) malloc(8*sizeof(char));
        if (host == NULL){
            stcp_debug(__func__, "ERROR", "failed to allocate host valriable memory\n");
            return -1;
        }
        end_point = (char *) malloc(2*sizeof(char));
        if (end_point == NULL){
            free(host);
            host = NULL;
            stcp_debug(__func__, "ERROR", "failed to allocate end_point valriable memory\n");
            return -1;
        }
        buff = (char *) malloc(9*sizeof(char));
        if (buff == NULL){
            free(host);
            free(end_point);
            host = NULL;
            end_point = NULL;
            stcp_debug(__func__, "ERROR", "failed to allocate buff valriable memory\n");
            return -1;
        }
        uint16_t idx_char_url = 0;
        uint16_t idx_char_buff = 0;
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
        host = NULL;
        if (_url[idx_char_url] == 0x00){
            free(end_point);
            free(buff);
            end_point = NULL;
            buff = NULL;
            strcpy(_end_point, "/");
            return 0;
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
            end_point = NULL;
            buff = NULL;
            strcpy(_end_point, "/");
            return 0;
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
        end_point = NULL;
        buff = NULL;
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

unsigned char *stcp_http_generate_multipart_header(char *_stcp_multipart_header_input, char *_boundary_output, uint16_t *_length_part){
    /* style: general_header_end_with_multipart/from-data|form_data_1|form_data_2|...|file */
    /* boundary style : --stcpMBoundaryxxxxxxxxxxxx */
    unsigned char *output_header = NULL;
    unsigned char *buff = NULL;
    buff = (unsigned char *) malloc(128 * sizeof(unsigned char));
    if (buff == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate buffer memory\n");
        return NULL;
    }
    uint16_t idx_header = 0;
    uint16_t pos_header = 0;
    uint16_t header_length = (uint16_t) strlen(_stcp_multipart_header_input);
    uint16_t idx_data = 0;
    uint16_t buff_size = 0;
    uint8_t num_of_from_data = 0;
    uint8_t num_tmp = 0;
    long stcp_time_boundary = time(NULL);

    memset(buff, 0x00, 32*sizeof(unsigned char));

    /* count number of from-data*/
    while(idx_header < header_length){
        if (_stcp_multipart_header_input[idx_header] == '|'){
            num_of_from_data++;
        }
        idx_header++;
    }
    if (num_of_from_data == 0){
        stcp_debug(__func__, "ERROR", "from-data is missing\n");
        free(buff);
        buff = NULL;
        return NULL;
    }
    /* get start point */
    idx_header = 0;
    while(idx_header < (header_length - 19)){
        memcpy(buff, _stcp_multipart_header_input + idx_header, 19);
        if (memcmp(buff, (unsigned char *)"multipart/form-data", 19) == 0){
            idx_header = idx_header + 18;
            break;
        }
        idx_header++;
    }

    header_length = idx_header + 37 + 4 + 29 + 2 + 38 + 1;
    output_header = (unsigned char *) malloc((header_length + 1) * sizeof(unsigned char *));
    if (output_header == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate header memory\n");
        free(buff);
        buff = NULL;
        return NULL;
    }
    memset(buff, 0x00, 32*sizeof(unsigned char));
    sprintf((char *) buff, "--stcpMBoundary%012li", stcp_time_boundary);
    strcpy(_boundary_output, (char *) buff);
    memset(output_header, 0x00, (header_length + 1) * sizeof(unsigned char *));
    memcpy(output_header, _stcp_multipart_header_input, (idx_header + 1));
    memcpy(output_header + (idx_header + 1), ";boundary=", 10);
    memcpy(output_header + (idx_header + 11), _boundary_output, 27);
    memcpy(output_header + (idx_header + 38), "\r\n\r\n--", 6);
    memcpy(output_header + (idx_header + 44), _boundary_output, 27);
    memcpy(output_header + (idx_header + 71), "\r\nContent-Disposition: form-data; name=\"", 40);
    pos_header = idx_header + 111;
    *_length_part = idx_header + 42;

    idx_header+=2;
    header_length = (uint16_t) strlen(_stcp_multipart_header_input);
    memset(buff, 0x00, 32*sizeof(unsigned char));
    buff_size = 32;

    do {
        if (_stcp_multipart_header_input[idx_header] == '=' && idx_data > 0){
            num_tmp++;
            if (num_tmp == 1){
                output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 6)*sizeof(unsigned char));
                memcpy(output_header + pos_header, buff, idx_data);
                memcpy(output_header + (pos_header + idx_data), "\"\r\n\r\n", 5);
                pos_header += idx_data + 5;
            }
            else if (num_tmp < num_of_from_data){
                output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 4 + 27 + 40 + 6)*sizeof(unsigned char));
                memcpy(output_header + pos_header, "\r\n--", 4);
                memcpy(output_header + (pos_header + 4), _boundary_output, 27);
                memcpy(output_header + (pos_header + 4 + 27), "\r\nContent-Disposition: form-data; name=\"", 40);
                memcpy(output_header + (pos_header + 4 + 27 + 40), buff, idx_data);
                memcpy(output_header + (pos_header + 4 + 27 + 40 + idx_data), "\"\r\n\r\n", 5);
                pos_header += idx_data + 4 + 27 + 40 + 5;
            }
            else {
                output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 4 + 27 + 40 + 14)*sizeof(unsigned char));
                memcpy(output_header + pos_header, "\r\n--", 4);
                memcpy(output_header + (pos_header + 4), _boundary_output, 27);
                memcpy(output_header + (pos_header + 4 + 27), "\r\nContent-Disposition: form-data; name=\"", 40);
                memcpy(output_header + (pos_header + 4 + 27 + 40), buff, idx_data);
                memcpy(output_header + (pos_header + 4 + 27 + 40 + idx_data), "\"; filename=\"", 13);
                pos_header += idx_data + 4 + 27 + 40 + 13;
            }
            idx_data = 0;
            if (buff_size != 32){
                buff_size = 32;
                buff = (unsigned char *) realloc(buff, buff_size*sizeof(unsigned char));
                memset(buff, 0x00, buff_size*sizeof(unsigned char));
            }
            else {
                memset(buff, 0x00, buff_size*sizeof(unsigned char));
            }
        }
        else if (_stcp_multipart_header_input[idx_header] == '|' && idx_data > 0){
            output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 1)*sizeof(unsigned char));
            memcpy(output_header + pos_header, buff, idx_data);
            pos_header += idx_data;
            idx_data = 0;
            if (buff_size != 32){
                buff_size = 32;
                buff = (unsigned char *) realloc(buff, buff_size*sizeof(unsigned char));
                memset(buff, 0x00, buff_size*sizeof(unsigned char));
            }
            else {
                memset(buff, 0x00, buff_size*sizeof(unsigned char));
            }
        }
        else if (_stcp_multipart_header_input[idx_header] == 0x00){
            output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 6)*sizeof(unsigned char));
            memcpy(output_header + pos_header, buff, idx_data);
            memcpy(output_header + (pos_header + idx_data), "\"\r\n\r\n", 5);
            pos_header += idx_data + 5;
            output_header[pos_header] = 0x00;
            idx_data = 0;
            if (buff_size != 32){
                buff_size = 32;
                buff = (unsigned char *) realloc(buff, buff_size*sizeof(unsigned char));
                memset(buff, 0x00, buff_size*sizeof(unsigned char));
            }
            else {
                memset(buff, 0x00, buff_size*sizeof(unsigned char));
            }
            break;
        }
        else {
            if (idx_data == buff_size - 2){
                buff_size += 8;
                buff = (unsigned char *) realloc(buff, buff_size*sizeof(unsigned char));
            }
            buff[idx_data] = _stcp_multipart_header_input[idx_header];
            idx_data++;
        }
        idx_header++;
    } while (idx_header <= header_length);

    *_length_part = (pos_header + 31 + 2) - *_length_part;

    free(buff);
    buff = NULL;

    return output_header;
}

unsigned char *stcp_http_request(char *_req_type, char *_url, char *_header, char *_content, stcp_request_type _request_type){
    long request_length = 0;
    if (_request_type != STCP_REQ_UPLOAD_FILE){
        if (_content != NULL){
            request_length = strlen(_content);
        }
    }
    else if (_content != NULL){
        request_length = stcp_get_file_size(_content);
        if (request_length < 0){
            stcp_debug(__func__, "ERROR", "request aborted.\n");
            return NULL;
        }
        else if (request_length == 0){
            stcp_debug(__func__, "WARNING", "file empety.request aborted.\n");
            return NULL;
        }
    }
    else {
        stcp_debug(__func__, "ERROR", "bad STCP request. process aborted.\n");
        return NULL;
    }
    char *message_request= NULL;
    char *host = NULL;
    char *end_point = NULL;
    unsigned char *response = NULL;
    char *protocol = NULL;
    char *boundary = NULL;
    uint32_t length_of_message = 0;
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
        message_request = NULL;
        return NULL;
    }
    end_point = (char *) malloc(strlen(_url) * sizeof(char));
    if (end_point == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate end_point variable memory\n");
        free(message_request);
        free(host);
        message_request = NULL;
        host = NULL;
        return NULL;
    }
    protocol = (char *) malloc(6 * sizeof(char));
    if (protocol == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate protocol variable memory\n");
        free(message_request);
        free(host);
        free(end_point);
        message_request = NULL;
        host = NULL;
        end_point = NULL;
        return NULL;
    }
    response = (unsigned char *) malloc(2 * sizeof(unsigned char));
    if (response == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate response variable memory\n");
        free(message_request);
        free(host);
        free(end_point);
        free(protocol);
        message_request = NULL;
        host = NULL;
        end_point = NULL;
        protocol = NULL;
        return NULL;
    }
    boundary = (char *) malloc(32 * sizeof(unsigned char));
    if (boundary == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate response variable memory\n");
        free(message_request);
        free(host);
        free(end_point);
        free(protocol);
        free(response);
        message_request = NULL;
        host = NULL;
        end_point = NULL;
        protocol = NULL;
        response = NULL;
        return NULL;
    }
    int8_t retval = stcp_url_parser(_url, host, protocol, end_point, &port);
    if (retval == -1){
        free(message_request);
        free(host);
        free(end_point);
        free(protocol);
        free(response);
        free(boundary);
        message_request = NULL;
        host = NULL;
        end_point = NULL;
        protocol = NULL;
        response = NULL;
        boundary = NULL;
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
    
    stcpSock socket_f;
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
        free(boundary)
        message_request = NULL;
        host = NULL;
        end_point = NULL;
        protocol = NULL;
        response = NULL;
        boundary = NULL;
        return NULL;
        #endif
    }
    if (socket_f.socket_f <= 0){
        free(message_request);
        free(host);
        free(end_point);
        free(protocol);
        free(boundary);
        message_request = NULL;
        host = NULL;
        end_point = NULL;
        protocol = NULL;
        boundary = NULL;
        response = (unsigned char *) realloc(response, 17*sizeof(unsigned char));
        strcpy((char *) response, "no route to host");
        return response;
    }

    if (_header != NULL && _content != NULL){
        if (_request_type != STCP_REQ_UPLOAD_FILE){
            length_of_message = length_of_message + strlen(_header) + strlen(_content);
            message_request = (char *) realloc(message_request, (length_of_message + 1)*sizeof(char));
            memset(message_request, 0x00, (length_of_message + 1)*sizeof(char));
            sprintf(message_request,
             "%s /%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "%s\r\n"
             "Content-Length: %li\r\n\r\n"
             "%s\r\n\r\n",
             _req_type,
             end_point,
             host,
             _header,
             request_length,
             _content
            );
        }
        else {
            if (strstr(_header, "multipart/form-data") == NULL){
                length_of_message = length_of_message + strlen(_header);
                message_request = (char *) realloc(message_request, (length_of_message + 1)*sizeof(char));
                memset(message_request, 0x00, (length_of_message + 1)*sizeof(char));
                sprintf(message_request,
                 "%s /%s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "%s\r\n"
                 "Content-Length: %li\r\n\r\n",
                 _req_type,
                 end_point,
                 host,
                 _header,
                 request_length
                );
            }
            else {
                uint16_t part_content_length = 0;
                memset(boundary, 0x00, 32*sizeof(char));
                char *header_part = (char *) stcp_http_generate_multipart_header(_header, boundary, &part_content_length);
                if (header_part != NULL){
                    length_of_message = length_of_message + strlen(header_part);
                    message_request = (char *) realloc(message_request, (length_of_message + 1)*sizeof(char));
                    memset(message_request, 0x00, (length_of_message + 1)*sizeof(char));
                    sprintf(message_request,
                     "%s /%s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Content-Length: %li\r\n"
                     "%s",
                     _req_type,
                     end_point,
                     host,
                     request_length + part_content_length,
                     header_part
                    );
                    free(header_part);
                    header_part = NULL;
                }
                else {
                    stcp_debug(__func__, "WARNING", "failed to generate multipart/form-data\n");
                    length_of_message = length_of_message + strlen(_header);
                    message_request = (char *) realloc(message_request, (length_of_message + 1)*sizeof(char));
                    memset(message_request, 0x00, (length_of_message + 1)*sizeof(char));
                    sprintf(message_request,
                     "%s /%s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "%s\r\n"
                     "Content-Length: %li\r\n\r\n",
                     _req_type,
                     end_point,
                     host,
                     _header,
                     request_length
                    );
                    free(boundary);
                    boundary = NULL;
                }
            }
        }
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
    if (stcp_setup_data.stcp_debug_mode == STCP_DEBUG_ON){
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
        if (_request_type == STCP_REQ_UPLOAD_FILE){
            stcp_send_file(socket_f, _content);
            if (strstr(_header, "multipart/form-data") != NULL && boundary != NULL){
                char *endboundary = stcp_http_content_generator(64, "\r\n--%s--", boundary);
                if (endboundary != NULL){
                    stcp_send_data(socket_f, (unsigned char *) endboundary, strlen(endboundary));
                    free(endboundary);
                    endboundary = NULL;
                }
                else {
                    stcp_debug(__func__, "WARNING", "failed to create end boundary\n");
                }
                free(boundary);
                boundary = NULL;
            }
        }
    }
    else {
        #ifdef __STCP_SSL__
        stcp_ssl_send_data(socket_f, (unsigned char *) message_request, strlen(message_request));
        if (_request_type == STCP_REQ_UPLOAD_FILE){
            stcp_ssl_send_file(socket_f, _content);
            if (strstr(_header, "multipart/form-data") != NULL && boundary != NULL){
                char *endboundary = stcp_http_content_generator(64, "\r\n--%s--", boundary);
                if (endboundary != NULL){
                    stcp_ssl_send_data(socket_f, (unsigned char *) endboundary, strlen(endboundary));
                    free(endboundary);
                    endboundary = NULL;
                }
                else {
                    stcp_debug(__func__, "WARNING", "failed to create end boundary\n");
                }
                free(boundary);
                boundary = NULL;
            }
        }
        #endif
    }

    free(message_request);
    free(host);
    free(end_point);
    message_request = NULL;
    host = NULL;
    end_point = NULL;

    int32_t bytes = 0;
    uint32_t total_bytes = 0;
    uint32_t total_bytes_tmp = 0;
    int8_t header_check_status = STCP_HEADER_CHECK;
    int8_t get_process = STCP_PROCESS_GET_HEADER;
    uint32_t content_length = 0;
    uint32_t download_counter = 0;
    uint8_t recv_trytimes = 0;
    int8_t transfer_encoding = 0;

    unsigned char *response_tmp = NULL;
    response_tmp = (unsigned char *) malloc((stcp_setup_data.stcp_size_per_recv + 1) * sizeof(unsigned char));
    if (response_tmp == NULL){
        free(protocol);
        free(response);
        protocol = NULL;
        response = NULL;
        stcp_debug(__func__, "ERROR", "failed to allocate response_tmp memory\n");
        return 0;
    }

    memset(response, 0x00, 2 * sizeof(char));
    do {
        memset(response_tmp, 0x00, stcp_setup_data.stcp_size_per_recv + 1);
        if (strcmp(protocol, "http") == 0){
            bytes = stcp_recv_data(socket_f, response_tmp, stcp_setup_data.stcp_size_per_recv);
        }
        else {
            #ifdef __STCP_SSL__
            bytes = stcp_ssl_recv_data(socket_f, response_tmp, stcp_setup_data.stcp_size_per_recv);
            #endif
        }
        if (bytes == -1){
            stcp_debug(__func__, "ERROR", "Lost Connection\n");
            break;
        }
        else if (bytes == 0){
            if (recv_trytimes == stcp_setup_data.stcp_max_recv_try) {
                recv_trytimes = 0;
                break;
            }
            recv_trytimes++;
            goto try_recv;
        }
        else if (recv_trytimes > 0){
            stcp_debug(__func__, "INFO", "reset recv try counter to zero\n");
            recv_trytimes = 0;
        }
        if (_request_type != STCP_REQ_DOWNLOAD_CONTENT || get_process == STCP_PROCESS_GET_HEADER){
            total_bytes_tmp = total_bytes_tmp + bytes;
            response = (unsigned char *) realloc(response, (total_bytes + bytes + 1) * sizeof(unsigned char));
            memcpy(response + total_bytes, response_tmp, bytes);
            response[total_bytes_tmp] = 0x00;
            if (get_process == STCP_PROCESS_GET_HEADER){
                if ((total_bytes > 4 && bytes > 0) || bytes > 4){
                    if ((total_bytes > 20 || bytes > 20) && header_check_status == STCP_HEADER_CHECK){
                        if (strstr((char *) response, "200 OK") == NULL){
                            header_check_status = STCP_HEADER_BLOCK;
                            if (_request_type != STCP_REQ_COMPLETE){
                                total_bytes = 0;
                                do {
                                    total_bytes++;
                                } while(response[total_bytes] != '\r');
                                response[total_bytes] = 0x00;
                                response = (unsigned char *) realloc(response, (total_bytes + 1)*sizeof(unsigned char));
                                break;
                            }
                        }
                        else if (_request_type == STCP_REQ_HTTP_STATUS_ONLY || _request_type == STCP_REQ_UPLOAD_FILE){
                            total_bytes = 0;
                            do {
                                total_bytes++;
                            } while(response[total_bytes] != '\r');
                            response[total_bytes] = 0x00;
                            response = (unsigned char *) realloc(response, (total_bytes + 1)*sizeof(unsigned char));
                            break;
                        }
                        else {
                            if (strstr((char *) response, "Transfer-Encoding: chunked") != NULL){
                                transfer_encoding = 1;
                            }
                            header_check_status = STCP_HEADER_PASS;
                        }
                    }
                    if (total_bytes == 0){
                        total_bytes = 4;
                        bytes = bytes - 4;
                    }
                    do {
                        if(response[total_bytes - 1] == '\n' && response[total_bytes - 2] == '\r' &&
                         response[total_bytes - 3] == '\n' && response[total_bytes - 4] == '\r'
                        ){
                            get_process = STCP_PROCESS_GET_CONTENT;
                            content_length = stcp_get_content_length((char *) response);

                            if (_request_type == STCP_REQ_HEADER_ONLY){
                                response[total_bytes] = 0x00;
                                response = (unsigned char *) realloc(response, (total_bytes + 1)*sizeof(unsigned char));
                                goto request_finished;
                            }

                            if (bytes > 0){
                                if (_request_type == STCP_REQ_DOWNLOAD_CONTENT){
                                    /* append file */
                                    if (download_file == NULL){
                                        stcp_debug(__func__, "ERROR", "failed to open config file\n");
                                    }
                                    else {
                                        memset(response_tmp, 0x00, (stcp_setup_data.stcp_size_per_recv + 1)*sizeof(char));
                                        memcpy(response_tmp, response + total_bytes, bytes);
                                        fprintf(download_file, "%s", response_tmp);
                                    }
                                    response[total_bytes] = 0x00;
                                    response = (unsigned char *) realloc(response, (total_bytes + 1)*sizeof(unsigned char));
                                }
                            }
                            break;
                        }
                        total_bytes++;
                        bytes--;
                    } while (bytes >= 0);
                }
            }
            total_bytes = total_bytes_tmp;
            if (get_process == STCP_PROCESS_GET_CONTENT && bytes > 0) {
                download_counter = download_counter + bytes;
                if (content_length > 0){
                    stcp_debug(__func__, "INFO", "get: %i/%i bytes\n", download_counter, content_length);
                }
                else{
                    if(response[total_bytes - 1] == '\n' && response[total_bytes - 2] == '\r' &&
                     response[total_bytes - 3] == '\n' && response[total_bytes - 4] == '\r' &&
                     transfer_encoding == 1
                    ){
                        stcp_debug(__func__, "INFO", "get: %i/unknown bytes - finished\n", download_counter);
                        break;
                    }
                    stcp_debug(__func__, "INFO", "get: %i/unknown bytes\n", download_counter);
                }
            }
            else if (get_process == STCP_PROCESS_GET_CONTENT){
                bytes = 1;
            }
            else {
                bytes = 1;
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

        try_recv:
            if(bytes == 0){
                stcp_debug(__func__, "WARNING", "try recv process (%i/%i)\n", recv_trytimes, stcp_setup_data.stcp_max_recv_try);
            }
    } while (bytes >= 0);

    request_finished:
        if (strcmp(protocol, "http") == 0){
            stcp_close(&socket_f);
        }
        else {
            #ifdef __STCP_SSL__
            stcp_ssl_close(&socket_f);
            #endif
        }
        free(protocol);
        protocol = NULL;
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
        free(response_tmp);
        response_tmp = NULL;
        if (strlen((char *) response) == 0){
            if (stcp_setup_data.stcp_timeout_sec == 0){
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

void stcp_close(stcpSock *init_data){
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
void stcp_ssl_close(stcpSock *init_data){
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
    buff_info = NULL;
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
    stcpSock init_data;
    struct sockaddr_in servaddr;

    const int16_t PACKET_SIZE = 64;
    const uint16_t PING_DELAY = 1000;
    char ip_address[16];

    struct stcp_ping_summary ping_data;
    memset(&ping_data, 0x00, sizeof(struct stcp_ping_summary));

    init_data.socket_f = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (init_data.socket_f == -1) {
        stcp_debug(__func__, "CRITICAL", "socket creation failed...\n");
        ping_data.state = -1;
        return ping_data;
    }
    else{
        stcp_debug(__func__, "INFO", "Socket successfully created : %d\n", init_data.socket_f);
        memset(&servaddr, 0x00, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(80);
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