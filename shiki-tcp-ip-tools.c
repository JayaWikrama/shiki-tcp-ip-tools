/** \file shiki-tcp-ip-tools.c
 * Copyright (C) 2019, 2020 Jaya Wikrama
 * 
 * Shiki TCP IP Tools (STCP) library provides the core API for TCP/IP, Webserver,
 * and other network communication purpose based on TCP/IP. This library writen
 * in C and compatible for C++ too. 
 * 
 * External Library Requirements:
 * - Shiki Linked List (SHILINK)
 * 
 * Release Note (After Nov 24 2020)
 * Ver.3.20.20.12.16
 * * Nov 24 2020, Jaya Wikrama <jayawikrama89@gmail.com>
 * -  Add Documentation
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
#include <dirent.h>
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
#define SA struct sockaddr
#define STCP_VER "3.19.20.11.17"

typedef enum {
    #ifdef __STCP_WEBSERVER__
    /* Server state */
    STCP_SERVER_RUNING = 0x00, /*!< default signal state of STCP WEBSERBVER when its run correctly */
    STCP_SERVER_STOP = 0x01, /*!< signal state to stop STCP WEBSERBVER */
    STCP_SERVER_STOPED = 0x02, /*!< signal state of STCP WEBSERBVER when that inform STCP WEBSERVER has been stoped correctly */
    #endif
    /* Data com type */
    STCP_TCP = 0x0a, /*!< TCP/IP Data Communication Type */
    STCP_SSL = 0x0b, /*!< SSL/TLS Data Communication Type */
    /* Process state */
    STCP_HEADER_CHECK = 0x10, /*!< STCP HTTP Client process flag when check collected header response from server */
    STCP_HEADER_PASS = 0x11, /*!< STCP HTTP Client process flag when all header response from server have been collected */
    STCP_HEADER_BLOCK = 0x12, /*!< STCP HTTP Client flag for BLOCK all invalid HTTP Header Response */
    STCP_PROCESS_GET_HEADER = 0x13, /*!< STCP HTTP Client process flag when collecting header response from server */
    STCP_PROCESS_GET_CONTENT = 0x14 /*!< STCP HTTP Client process flag when collecting content response from server */
} stcp_const;

struct stcp_setup_var{
    int8_t stcp_lock_setup; /*!< flag LOCK/UNLOCK global setup */
    int8_t stcp_debug_mode; /*!< flag to determine that debug is enable/disabled */
    int8_t stcp_retry_mode; /*!< flag of retry routine for initialize Server/Client */
    uint8_t stcp_max_recv_try; /*!< maximum try times to receive packet */
    uint16_t stcp_timeout_sec; /*!< timeout of connect, accept, send, and receive in seconds */
    uint16_t stcp_timeout_millisec; /*!< timeout of connect, accept, send, and receive in milliseconds */
    uint32_t stcp_size_per_recv; /*!< size of maximum date that can be received for a single process */
    uint32_t stcp_size_per_send; /*!< size of maximum date that can be send for a single process */
};

#ifdef __STCP_WEBSERVER__
struct stcp_webserver_setup_var {
    uint16_t stcp_keepalive_sec; /*!< time in seconds that determine how long connection in STCP WEBSERVER will be keep alive after last transaction/communication */
    uint16_t stcp_keepalive_millisec; /*!< time in milliseconds that determine how long connection in STCP WEBSERVER will be keep alive after last transaction/communication */
    uint16_t stcp_max_elapsed_connection; /*!< time in seconds that determine how long single request/transaction can be accepted in STCP WEBSERVER */
    uint16_t stcp_slow_http_attack_blocking_time; /*!< time in seconds that determine how long client will be block in STCP WEBSERVER after the client is suspected of conducting an abnormal transaction/request */
    uint8_t stcp_slow_http_attack_counter_accepted; /*!< counter that determine how many times client will be set as suspected client that conducting an abnormal transaction/request in STCP WEBSERVER */
    uint32_t stcp_max_received_header; /*!< size of maximum accepted header in STCP WEBSERVICE */
    uint32_t stcp_max_received_data; /*!< size of maximum accepted data in STCP WEBSERVICE */
    #ifdef __STCP_SSL__
    stcp_ssl_webserver_verify_mode stcp_sslw_verify_mode; /*!< SSL Webserver Verify mode */
    #endif
};
#endif

struct stcp_setup_var stcp_setup_data = {
    0x00,
    STCP_DEBUG_OFF,
    WITHOUT_RETRY,
    3,
    0,
    0,
    128,
    128
};

#ifdef __STCP_WEBSERVER__
struct stcp_webserver_setup_var stcp_webserver_setup_data = {
    0,
    0,
    60,
    300,
    3,
    4096,
    4294967290
    #ifdef __STCP_SSL__
    ,
    STCP_SSL_WEBSERVER_WITHOUT_VERIFY_CLIENT
    #endif
};
#endif

#ifdef __STCP_SSL__
    SHLink stcp_certkey_collection = NULL;
#endif

#ifdef __STCP_WEBSERVER__
int8_t stcp_webserver_init_state = 0;
int8_t stcp_server_state = 0;

static const char *stcp_day_str[] = {
    "Sun",
    "Mon",
    "Tue",
    "Wed",
    "Thu",
    "Fry",
    "Sat"
};
static const char *stcp_mon_str[] = {
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec"
};
#endif

#ifndef __STCP_DONT_USE_CLIENT__
char stcp_file_name[STCP_MAX_LENGTH_FILE_NAME];
#endif

static int8_t stcp_check_ip(const char *_ip_address);
static unsigned long stcp_get_content_length(const char *_text_source);
static unsigned char *stcp_select_content(unsigned char *response, uint32_t _content_length);

/**
 * Main debug API on STCP Library
 * @param _function_name a constant character pointer
 * @param _debug_type a member of enum on __stcp_debug_type__ (you can find this on header file)
 * @param _debug_msg a constant character of debug format or debug message followed by debug arguments (printf style)
 */
inline void stcp_debug(const char *_function_name, stcp_debug_type _debug_type, const char *_debug_msg, ...){
	if (stcp_setup_data.stcp_debug_mode || _debug_type){
        struct tm *d_tm = NULL;
        struct timeval tm_debug;
        uint16_t msec = 0;
		
	    gettimeofday(&tm_debug, NULL);
	    d_tm = localtime(&tm_debug.tv_sec);
        msec = tm_debug.tv_usec/1000;

        #ifdef __linux__
            if (_debug_type == STCP_DEBUG_INFO)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;32m INFO\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
            else if (_debug_type == STCP_DEBUG_DOWNLOAD)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;32m DOWNLOAD\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
            else if (_debug_type == STCP_DEBUG_VERSION)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;32m VERSION\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
            else if (_debug_type == STCP_DEBUG_WEBSERVER)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;32m WEBSERVER INFO\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
    	    else if (_debug_type == STCP_DEBUG_WARNING)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;33m WARNING\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
    	    else if (_debug_type == STCP_DEBUG_ERROR)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;31m ERROR\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
            else if (_debug_type == STCP_DEBUG_CRITICAL)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;31m CRITICAL\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
	    #else
            printf("%02d-%02d-%04d %02d:%02d:%02d.%03d [%02x]: %s: ",
             d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
             msec, _debug_type, _function_name
            );
        #endif

        va_list aptr;
        va_start(aptr, _debug_msg);
	    vfprintf(stdout, _debug_msg, aptr);
	    va_end(aptr);
    }
}

#ifndef __STCP_DONT_USE_CLIENT__
/**
 * Connect to TCP/IP Server with timeout parameter (not visible in header file as default)
 * @param[in] stcp_socket_f an integer parameter (socket descriptor)
 * @param[in] addr a pointer of sockaddr structur
 * @param[in] addrlen an unsigned long integer (size_t) parameter
 * @param[in] stcp_timeout a pointer of timeval structur (timeout of connect process)
 * @return 0 if success, 1 if fail
 */
static int8_t stcp_connect_with_timeout (
 int stcp_socket_f,
 struct sockaddr * addr,
 size_t addrlen,
 struct timeval * stcp_timeout
){
	int retval = 0;
    int fcntl_flags = 0;
	if ((fcntl_flags = fcntl (stcp_socket_f, F_GETFL, NULL)) < 0) {
		return 0x01;
	}
	if (fcntl (stcp_socket_f, F_SETFL, fcntl_flags | O_NONBLOCK) < 0) {
		return 0x01;
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
		return 0x01;
	}

	if (retval < 0) {
		return 0x01;
	}
	else if (retval == 0) {
		errno = ETIMEDOUT;
		return 0x01;
	}
	else {
		socklen_t len = sizeof (fcntl_flags);
		if (getsockopt (stcp_socket_f, SOL_SOCKET, SO_ERROR, &fcntl_flags, &len) < 0) {
			return 0x01;
		}
		if (fcntl_flags) {
			errno = fcntl_flags;
			return 0x01;
		}
	}
	return 0x00;
}
#endif

/**
 * Check Address is valid IP or not (not visible in header file as default)
 * @param[in] stcp_socket_f an integer parameter (socket descriptor)
 * @param[in] addr a pointer of sockaddr structur
 * @param[in] addrlen an unsigned long integer (size_t) parameter
 * @param[in] stcp_timeout a pointer of timeval structur (timeout of connect process)
 * @return 0 if success, 1 if length is invalid, 2 if number of dots (.) is invalid, 3 if value blocks is invalid
 */
static int8_t stcp_check_ip(const char *_ip_address){
    /* check length */
    if (strlen(_ip_address) > 15){
        return 0x01;
    }
    /* check point and value per point */
    int8_t point_counter = 0;
    int8_t aviable_value_per_point[4];
    memset(aviable_value_per_point, 0x00, sizeof(aviable_value_per_point));
    int i = 0;
    for (i=0; i < (int) strlen(_ip_address); i++){
        if(_ip_address[i] == '.'){
            point_counter++;
        }
        else if (point_counter < 4){
            aviable_value_per_point[point_counter]++;
        }
        else {
            return 0x02;
        }
    }
    if (point_counter != 3){
        return 0x02;
    }
    if (aviable_value_per_point[0] == 0 ||
     aviable_value_per_point[1] == 0 ||
     aviable_value_per_point[2] == 0 ||
     aviable_value_per_point[3] == 0
    ){
        return 0x03;
    }
    if (aviable_value_per_point[0] > 3 ||
     aviable_value_per_point[1] > 3 ||
     aviable_value_per_point[2] > 3 ||
     aviable_value_per_point[3] > 3
    ){
        return 0x03;
    }
    return 0x00;
}

/**
 * Check STCP Library Version
 * @param[out] _version char pointer that will be store version of STCP Library as string
 * @return long integer format of version
 */
long stcp_get_version(char *_version){
    strcpy(_version, STCP_VER);
    long version_in_long = 0;
    uint8_t idx_ver = 0x00;
    uint8_t multiplier = 0x0a;
    while(idx_ver < 0x0d){
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

/**
 * Print Version of STCP Library
 */
void stcp_view_version(){
    stcp_debug(__func__, STCP_DEBUG_VERSION, "%s\n", STCP_VER);
}

/**
 * Setup common routine of STCP Library
 * @param[in] _setup_parameter a member of enum on __stcp_setup_parameter__ (you can find this on header file)
 * @param[in] _value an unsigned integer (32 bit) parameter
 * @return 0 if success, 1 if parameter or value is invalid, and 2 if setup was locked (8 bit integer value)
 */
int8_t stcp_setup(stcp_setup_parameter _setup_parameter, uint32_t _value){
    if (stcp_setup_data.stcp_lock_setup){
        stcp_debug(__func__, STCP_DEBUG_WARNING, "SETUP LOCKED!!!\n");
        return 0x02;
    }
    if (_setup_parameter == STCP_SET_TIMEOUT_IN_SEC){
        if (_value < 0 || _value > 999){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "invalid value\n");
            return 0x01;
        }
        stcp_setup_data.stcp_timeout_sec = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_TIMEOUT_IN_MILLISEC){
        if (_value < 0 || _value > 999){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "invalid value\n");
            return 0x01;
        }
        stcp_setup_data.stcp_timeout_millisec = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_DEBUG_MODE){
        if ((int8_t)_value == STCP_DEBUG_ON || (int8_t)_value == STCP_DEBUG_OFF){
            stcp_setup_data.stcp_debug_mode = (int8_t)_value;
        }
        else {
            stcp_debug(__func__, STCP_DEBUG_WARNING, "wrong value\n");
            return 0x01;
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
            stcp_debug(__func__, STCP_DEBUG_WARNING, "wrong value\n");
            return 0x01;
        }
    }
    else {
        stcp_debug(__func__, STCP_DEBUG_WARNING, "wrong parameters\n");
        return 0x01;
    }
    return 0x00;
}

#ifdef __STCP_WEBSERVER__
/**
 * Setup webserver routine of STCP Library
 * @param[in] _setup_parameter a member of enum on __stcp_webserver_setup_parameter__ (you can find this on header file)
 * @param[in] _value an unsigned integer (32 bit) parameter
 * @return 0 if success, 1 if parameter or value is invalid, and 2 if setup was locked (8 bit integer value)
 */
int8_t stcp_webserver_setup(stcp_webserver_setup_parameter _setup_parameter, uint32_t _value){
    if (stcp_setup_data.stcp_lock_setup){
        stcp_debug(__func__, STCP_DEBUG_WARNING, "SETUP LOCKED!!!\n");
        return 0x02;
    }
    if (_setup_parameter == STCP_SET_KEEP_ALIVE_TIMEOUT_IN_SEC){
        if (_value < 0 || _value > 30){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "invalid value\n");
            return 0x01;
        }
        stcp_webserver_setup_data.stcp_keepalive_sec = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_KEEP_ALIVE_TIMEOUT_IN_MILLISEC){
        if (_value < 0 || _value > 999){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "invalid value\n");
            return 0x01;
        }
        stcp_webserver_setup_data.stcp_keepalive_millisec = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_MAX_ELAPSED_CONNECTION){
        if (_value <= 0 || _value > 30000){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "invalid value\n");
            return 0x01;
        }
        stcp_webserver_setup_data.stcp_max_elapsed_connection = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_SLOW_HTTP_ATTACK_BLOCKING_TIME){
        if (_value <= 2 || _value > 3000){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "invalid value\n");
            return 0x01;
        }
        stcp_webserver_setup_data.stcp_slow_http_attack_blocking_time = (uint16_t)_value;
    }
    else if (_setup_parameter == STCP_SET_SLOW_HTTP_ATTACK_COUNTER_ACCEPTED){
        if (_value <= 0 || _value > 64){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "invalid value\n");
            return 0x01;
        }
        stcp_webserver_setup_data.stcp_slow_http_attack_counter_accepted = (uint8_t)_value;
    }
    else if (_setup_parameter == STCP_SET_MAX_RECEIVED_HEADER){
        if (_value <= 0 || _value > 10240){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "invalid value\n");
            return 0x01;
        }
        stcp_webserver_setup_data.stcp_max_received_header = (uint32_t)_value;
    }
    else if (_setup_parameter == STCP_SET_MAX_RECEIVED_DATA){
        if (_value <= 0 || _value > 4294967290){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "invalid value\n");
            return 0x01;
        }
        stcp_webserver_setup_data.stcp_max_received_data = (uint32_t)_value;
    }
    #ifdef __STCP_SSL__
    else if (_setup_parameter == STCP_SET_WEBSERVER_VERIFY_CERT_MODE){
        if ((int8_t)_value == STCP_SSL_WEBSERVER_WITHOUT_VERIFY_CLIENT ||
         (int8_t)_value == STCP_SSL_WEBSERVER_VERIFY_REMOTE_CLIENT){
            stcp_webserver_setup_data.stcp_sslw_verify_mode = (stcp_ssl_webserver_verify_mode) _value;
        }
        else {
            stcp_debug(__func__, STCP_DEBUG_WARNING, "wrong value\n");
            return 0x01;
        }
    }
    #endif
    else {
        stcp_debug(__func__, STCP_DEBUG_WARNING, "wrong parameters\n");
        return 0x01;
    }
    return 0x00;
}
#endif

/**
 * Lock the setup routine of STCP Library
 */
void stcp_lock_setup(){
    stcp_setup_data.stcp_lock_setup = 0x01;
}

/**
 * Unlock the setup routine of STCP Library
 */
void stcp_unlock_setup(){
    stcp_setup_data.stcp_lock_setup = 0x00;
}

#ifdef __STCP_SSL__
/**
 * Add the certificate and/or key for SSL/TLS communication purpose to __stcp_certkey_collection__ list
 * @param[in] _type a member of enum on __stcp_ssl_certkey_type__ (you can find this on header file)
 * @param[in] _host a constant character that inform the target host address
 * @param[in] _certkey a constant character of certificate/key (in path file form or content of certificate/key)
 * @return 0 if success, 1 if parameter or value is invalid, and 2 or 3 if failed to add certificate/key (8 bit integer value)
 */
int8_t stcp_ssl_add_certkey(stcp_ssl_certkey_type _type, const char *_host, const char *_certkey){
    if (_type < STCP_SSL_CERT_TYPE_FILE || _type > STCP_SSL_CACERT_TYPE_TEXT){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_WARNING, "wrong parameters\n");
        #endif
        return 0x01;
    }
    char buffkey[15 + strlen(_host)];
    memset(buffkey, 0x00, sizeof(buffkey));
    if (strstr(_host, "https://") != NULL){
        _host += 8;
    }
    else if (strstr(_host, "http://") != NULL){
        _host += 7;
    }
    if (_type == STCP_SSL_CERT_TYPE_FILE){
        sprintf(buffkey, "stcpsslcrtfile%s", _host);
    }
    else if (_type == STCP_SSL_CERT_TYPE_TEXT){
        sprintf(buffkey, "stcpsslcrttext%s", _host);
    }
    else if (_type == STCP_SSL_KEY_TYPE_FILE){
        sprintf(buffkey, "stcpsslkeyfile%s", _host);
    }
    else if (_type == STCP_SSL_KEY_TYPE_TEXT){
        sprintf(buffkey, "stcpsslkeytext%s", _host);
    }
    else if (_type == STCP_SSL_CACERT_TYPE_FILE){
        sprintf(buffkey, "stcpsslcacfile%s", _host);
    }
    else if (_type == STCP_SSL_CACERT_TYPE_TEXT){
        sprintf(buffkey, "stcpsslcactext%s", _host);
    }
    if (shilink_count_data_by_key(stcp_certkey_collection, (void *)buffkey, strlen(buffkey)) > 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_INFO, "certkey for %s have been added. process aborted\n", _host);
        #endif
        return 0x01;
    }
    SHLinkCustomData certkey_additional_data;
    if (shilink_fill_custom_data(
     &certkey_additional_data,
     (const void *) buffkey,
     (uint16_t) strlen(buffkey),
     (const void *) _certkey,
     strlen(_certkey),
     SL_TEXT
    ) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to fill data\n");
        #endif
        return 0x02;
    }
    if (shilink_append(&stcp_certkey_collection, certkey_additional_data) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to insert data\n");
        #endif
        return 0x03;
    }
    return 0x00;
}

/**
 * Remove the certificate and/or key for SSL/TLS communication purpose to __stcp_certkey_collection__ list
 * @param[in] _type a member of enum on __stcp_ssl_certkey_type__ (you can find this on header file)
 * @param[in] _host a constant character that inform the target host address
 * @param[in] _certkey a constant character of certificate/key (in path file form or content of certificate/key)
 * @return 0 if success, 1 if parameter or value is invalid, and 2 or 3 if failed to remove certificate/key (8 bit integer value)
 */
int8_t stcp_ssl_remove_certkey(stcp_ssl_certkey_type _type, const char *_host, const char *_certkey){
    if (_type < STCP_SSL_CERT_TYPE_FILE || _type > STCP_SSL_CACERT_TYPE_TEXT){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_WARNING, "wrong parameters\n");
        #endif
        return 0x01;
    }
    char buffkey[15 + strlen(_host)];
    memset(buffkey, 0x00, sizeof(buffkey));
    if (strstr(_host, "https://") != NULL){
        _host += 8;
    }
    else if (strstr(_host, "http://") != NULL){
        _host += 7;
    }
    if (_type == STCP_SSL_CERT_TYPE_FILE){
        sprintf(buffkey, "stcpsslcrtfile%s", _host);
    }
    else if (_type == STCP_SSL_CERT_TYPE_TEXT){
        sprintf(buffkey, "stcpsslcrttext%s", _host);
    }
    else if (_type == STCP_SSL_KEY_TYPE_FILE){
        sprintf(buffkey, "stcpsslkeyfile%s", _host);
    }
    else if (_type == STCP_SSL_KEY_TYPE_TEXT){
        sprintf(buffkey, "stcpsslkeytext%s", _host);
    }
    else if (_type == STCP_SSL_CACERT_TYPE_FILE){
        sprintf(buffkey, "stcpsslcacfile%s", _host);
    }
    else if (_type == STCP_SSL_CACERT_TYPE_TEXT){
        sprintf(buffkey, "stcpsslcactext%s", _host);
    }
    if (shilink_count_data_by_key(stcp_certkey_collection, (void *)buffkey, strlen(buffkey)) > 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_INFO, "certkey for %s not exist\n", _host);
        #endif
        return 0x01;
    }
    SHLinkCustomData certkey_additional_data;
    if (shilink_fill_custom_data(
     &certkey_additional_data,
     (const void *) buffkey,
     (uint16_t) strlen(buffkey),
     (const void *) _certkey,
     strlen(_certkey),
     SL_TEXT
    ) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to fill data\n");
        #endif
        return 0x02;
    }
    if (shilink_delete(&stcp_certkey_collection, certkey_additional_data) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to insert data\n");
        #endif
        return 0x03;
    }
    return 0;
}

/**
 * Get certificate for SSL/TLS communication purpose from __stcp_certkey_collection__ list
 * @param[in] _host a constant character that inform the target host address
 * @param[in] _type a member of enum on __stcp_ssl_certkey_type__ (you can find this on header file)
 * @return unsigned char pointer of certificate information if success (dont free this pointer), NULL if failed
 */
unsigned char *stcp_ssl_get_cert(const char *_host, stcp_ssl_certkey_type *_type){
    SHLinkCustomData sslcertres;
    char buff[15 + strlen(_host)];
    memset(buff, 0x00, sizeof(buff));
    if (strstr(_host, "https://") != NULL){
        _host += 8;
    }
    else if (strstr(_host, "http://") != NULL){
        _host += 7;
    }
    sprintf(buff, "stcpsslcrtfile%s", _host);
    if (shilink_search_data_by_position(
     stcp_certkey_collection,
     (const void *) buff,
     (uint16_t) strlen(buff),
     0,
     &sslcertres
    ) == 0){
        *_type = STCP_SSL_CERT_TYPE_FILE;
        return (unsigned char *) sslcertres.sl_value;
    }
    memset(buff, 0x00, sizeof(buff));
    sprintf(buff, "stcpsslcrttext%s", _host);
    if (shilink_search_data_by_position(
     stcp_certkey_collection,
     (const void *) buff,
     (uint16_t) strlen(buff),
     0,
     &sslcertres
    ) == 0){
        *_type = STCP_SSL_CERT_TYPE_TEXT;
        return (unsigned char *) sslcertres.sl_value;
    }
    return NULL;
}

/**
 * Get key for SSL/TLS communication purpose from __stcp_certkey_collection__ list
 * @param[in] _host a constant character that inform the target host address
 * @param[in] _type a member of enum on __stcp_ssl_certkey_type__ (you can find this on header file)
 * @return unsigned char pointer of key information if success (dont free this pointer), NULL if failed
 */
unsigned char *stcp_ssl_get_key(const char *_host, stcp_ssl_certkey_type *_type){
    SHLinkCustomData sslcertres;
    char buff[15 + strlen(_host)];
    memset(buff, 0x00, sizeof(buff));
    if (strstr(_host, "https://") != NULL){
        _host += 8;
    }
    else if (strstr(_host, "http://") != NULL){
        _host += 7;
    }
    sprintf(buff, "stcpsslkeyfile%s", _host);
    if (shilink_search_data_by_position(
     stcp_certkey_collection,
     (const void *) buff,
     (uint16_t) strlen(buff),
     0,
     &sslcertres
    ) == 0){
        *_type = STCP_SSL_KEY_TYPE_FILE;
        return (unsigned char *) sslcertres.sl_value;
    }
    memset(buff, 0x00, sizeof(buff));
    sprintf(buff, "stcpsslkeytext%s", _host);
    if (shilink_search_data_by_position(
     stcp_certkey_collection,
     (const void *) buff,
     (uint16_t) strlen(buff),
     0,
     &sslcertres
    ) == 0){
        *_type = STCP_SSL_KEY_TYPE_TEXT;
        return (unsigned char *) sslcertres.sl_value;
    }
    return NULL;
}

/**
 * Get cacert for SSL/TLS communication purpose from __stcp_certkey_collection__ list
 * @param[in] _host a constant character that inform the target host address
 * @param[in] _type a member of enum on __stcp_ssl_certkey_type__ (you can find this on header file)
 * @return unsigned char pointer of cacert information if success (dont free this pointer), NULL if failed
 */
unsigned char *stcp_ssl_get_cacert(const char *_host, stcp_ssl_certkey_type *_type){
    SHLinkCustomData sslcertres;
    char buff[15 + strlen(_host)];
    memset(buff, 0x00, sizeof(buff));
    if (strstr(_host, "https://") != NULL){
        _host += 8;
    }
    else if (strstr(_host, "http://") != NULL){
        _host += 7;
    }
    sprintf(buff, "stcpsslcacfile%s", _host);
    if (shilink_search_data_by_position(
     stcp_certkey_collection,
     (const void *) buff,
     (uint16_t) strlen(buff),
     0,
     &sslcertres
    ) == 0){
        *_type = STCP_SSL_CACERT_TYPE_FILE;
        return (unsigned char *) sslcertres.sl_value;
    }
    memset(buff, 0x00, sizeof(buff));
    sprintf(buff, "stcpsslcactext%s", _host);
    if (shilink_search_data_by_position(
     stcp_certkey_collection,
     (const void *) buff,
     (uint16_t) strlen(buff),
     0,
     &sslcertres
    ) == 0){
        *_type = STCP_SSL_CACERT_TYPE_TEXT;
        return (unsigned char *) sslcertres.sl_value;
    }
    return NULL;
}

/**
 * Create Certificate from PEM Text Buffer
 * @param[in] _sslCertKey an unsigned constant character pointer of PEM Text Buffer
 * @return X509 Certificate if success, NULL if failed
 */
X509 *stcp_ssl_create_cert_from_text(const unsigned char *_sslCertKey){
    BIO *tmpBio = NULL;
    X509 *tmpCertKey = NULL;
    tmpBio = BIO_new_mem_buf((void *) _sslCertKey, -1);
    if (tmpBio == NULL){
        return NULL;
    }
    tmpCertKey = PEM_read_bio_X509(tmpBio, NULL, 0, NULL);
    BIO_set_close(tmpBio, BIO_CLOSE);
    BIO_free(tmpBio);
    return tmpCertKey;
}

/**
 * Create Certificate Key from PEM Text Buffer
 * @param[in] _sslCertKey an unsigned constant character pointer of PEM Text Buffer
 * @return RSA Certificate Key if success, NULL if failed
 */
RSA *stcp_ssl_create_key_from_text(const unsigned char *_sslCertKey){
    BIO *tmpBio = NULL;
    RSA *tmpCertKey = NULL;
    tmpBio = BIO_new_mem_buf((void *) _sslCertKey, -1);
    if (tmpBio == NULL){
        return NULL;
    }
    tmpCertKey = PEM_read_bio_RSAPrivateKey(tmpBio, NULL, 0, NULL);
    BIO_set_close(tmpBio, BIO_CLOSE);
    BIO_free(tmpBio);
    return tmpCertKey;
}

/**
 * clear and free __stcp_certkey_collection__ list
 */
void stcp_ssl_clean_certkey_collection(){
    shilink_free(&stcp_certkey_collection);
    stcp_certkey_collection = NULL;
}
#endif

#ifndef __STCP_DONT_USE_CLIENT__
/**
 * set default file name of downloaded file from __stcp_http_request__ function
 * @param[in] _file_name a constant char that inform the file name
 * @return 0 if success, 1 if length of file name is invalid (8 bit integer value)
 */
int8_t stcp_set_download_file_name(const char* _file_name){
    if (strlen(_file_name) > STCP_MAX_LENGTH_FILE_NAME){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_WARNING, "file name to long. max:%d character\n", STCP_MAX_LENGTH_FILE_NAME);
        #endif
        return 0x01;
    }
    strcpy(stcp_file_name, _file_name);
    return 0x00;
}
#endif

/**
 * Initialize TCP/IP Server for single accept routines and one client only
 * @param[in] ADDRESS a constant character that inform the server address
 * @param[in] PORT an unsigned short parameter that inform the server port
 * @return stcpSock (__socket_f__ (member of stcpSock) > 0 if success)
 */
stcpSock stcp_server_init(const char *ADDRESS, uint16_t PORT){
    stcpSock init_data;
    init_data.socket_f = 0;
    init_data.connection_f = 0;
    socklen_t len;
    int8_t retval = 0x00;
    struct sockaddr_in servaddr, cli;
    do{
        init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
        if (init_data.socket_f == -1) {
            stcp_debug(__func__, STCP_DEBUG_CRITICAL, "socket creation failed...\n");
            retval = 0x01;
        }
        else{
            retval = 0x00;
            stcp_debug(__func__, STCP_DEBUG_INFO, "Socket successfully created : %d\n", init_data.socket_f);
            memset(&servaddr, 0x00, sizeof(servaddr));
            servaddr.sin_family = AF_INET;
            servaddr.sin_port = (in_port_t) htons(PORT);
            if(stcp_check_ip(ADDRESS) != 0){
                struct hostent *host = NULL;
                host = gethostbyname(ADDRESS);
                if (host != NULL){
                    servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
                }
                else {
                    stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to get host by name\n", ADDRESS);
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
                stcp_debug(__func__, STCP_DEBUG_CRITICAL, "socket bind failed...\n");
                if (stcp_setup_data.stcp_retry_mode == 1) stcp_debug(__func__, STCP_DEBUG_INFO, "trying to create a socket...\n");
                retval = 0x02; 
                close(init_data.socket_f);
                init_data.socket_f = 0;
                sleep(1);
            }
            else{
                stcp_debug(__func__, STCP_DEBUG_INFO, "Socket successfully binded..\n");

                if ((listen(init_data.socket_f, 5)) != 0) { 
                    stcp_debug(__func__, STCP_DEBUG_CRITICAL, "Listen failed...\n");
                    retval = 0x03;
                    close(init_data.socket_f);
                    init_data.socket_f = 0;
                }
                else{
                    stcp_debug(__func__, STCP_DEBUG_INFO, "Server listening..\n"); 
                    len = sizeof(cli);

                    init_data.connection_f = accept(init_data.socket_f, (SA*)&cli, &len);

                    if (init_data.connection_f < 0) { 
                        stcp_debug(__func__, STCP_DEBUG_CRITICAL, "server acccept failed...\n"); 
                        retval = 0x04;
                    }
                    else{
                        stcp_debug(__func__, STCP_DEBUG_INFO, "server acccept the client...\n");
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
    } while (retval && stcp_setup_data.stcp_retry_mode == INFINITE_RETRY);
    return init_data;
}

#ifdef __STCP_WEBSERVER__
/**
 * Initialize STCP Webserver Standard variable/parameters (allocate memmory and set default value of parameters)
 * @param[in] _stcpWI a pointer of __stcpWInfo__ (struct stcp_webserver_info)
 * @param[in] _stcpWH a pointer of __stcpHead__ (struct stcp_webserver_header)
 * @param[in] _stcpWList a pointer of __stcpWList__ (SHLink)
 * @return 0 if success or 1 if failed to allocate memmory (8 bit integer value)
 */
int8_t stcp_http_webserver_init(stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList *_stcpWList){
    stcpWInfo stcpWI;
    stcpWHead stcpWH;

    stcpWI.server_header = NULL;
    stcpWI.rcv_header = NULL;
    stcpWI.rcv_content = NULL;
    stcpWH.content_type = NULL;
    stcpWH.accept_type = NULL;

    *_stcpWList = NULL;
    stcpWI.server_header = (char *) malloc(8*sizeof(char));
    if (stcpWI.server_header == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate server_header memory\n");
        #endif
        return 0x01;
    }
    stcpWI.rcv_header = (unsigned char *) malloc(8*sizeof(unsigned char));
    if (stcpWI.rcv_header == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate rcv_header memory\n");
        #endif
        goto stcp_err_1;
    }
    stcpWI.rcv_content = (unsigned char *) malloc(8*sizeof(unsigned char));
    if (stcpWI.rcv_content == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate rcv_content memory\n");
        #endif
        goto stcp_err_2;
    }
    stcpWI.ipaddr = (char *) malloc(16*sizeof(char));
    if (stcpWI.ipaddr == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate ipaddr memory\n");
        #endif
        goto stcp_err_3;
    }
    stcpWH.content_type = (char *) malloc(32*sizeof(char));
    if (stcpWH.content_type == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate content_type memory\n");
        #endif
        goto stcp_err_4;
    }
    stcpWH.accept_type = (char *) malloc(8*sizeof(char));
    if (stcpWH.accept_type == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate accept_type memory\n");
        #endif
        goto stcp_err_5;
    }

    strcpy(stcpWH.content_type, "text/html; charset=ISO-8859-1");
    strcpy(stcpWH.accept_type, "*/*");
    stcp_webserver_init_state = 1;

    *_stcpWI = stcpWI;
    *_stcpWH = stcpWH;

    return 0x00;

    stcp_err_5:
        free(stcpWH.content_type);
        stcpWH.content_type = NULL;
    stcp_err_4:
        free(stcpWI.ipaddr);
        stcpWI.ipaddr = NULL;
    stcp_err_3:
        free(stcpWI.rcv_content);
        stcpWI.rcv_content = NULL;
    stcp_err_2:
        free(stcpWI.rcv_header);
        stcpWI.rcv_header = NULL;
    stcp_err_1:
        free(stcpWI.server_header);
        stcpWI.server_header = NULL;
        return 0x01;
}

/**
 * Set value of STCP Webserver Standard variable/parameters to default value
 * @param[in] _stcpWI a pointer of __stcpWInfo__ (struct stcp_webserver_info)
 * @param[in] _stcpWH a pointer of __stcpHead__ (struct stcp_webserver_header)
 */
static void stcp_http_webserver_bzero(stcpWInfo *_stcpWI, stcpWHead *_stcpWH){
    _stcpWI->rcv_header = (unsigned char *) realloc(_stcpWI->rcv_header, 8*sizeof(unsigned char));
    _stcpWI->rcv_content = (unsigned char *) realloc(_stcpWI->rcv_content, 8*sizeof(unsigned char));

    memset(_stcpWI->rcv_header, 0x00, 8*sizeof(unsigned char));
    memset(_stcpWI->rcv_content, 0x00, 8*sizeof(unsigned char));

    memset(&(_stcpWI->request), 0x00, sizeof(_stcpWI->request));
    memset(&(_stcpWI->rcv_endpoint), 0x00, sizeof(_stcpWI->rcv_endpoint));
    memset(&(_stcpWI->rcv_boundary), 0x00, sizeof(_stcpWI->rcv_boundary));
    memset(&(_stcpWI->data_end_point), 0x00, sizeof(_stcpWI->data_end_point));
    memset(&(_stcpWI->rcv_content_type), 0x00, sizeof(_stcpWI->rcv_content_type));
    memset(&(_stcpWI->rcv_acception_type), 0x00, sizeof(_stcpWI->rcv_acception_type));
    memset(&(_stcpWI->rcv_auth), 0x00, sizeof(_stcpWI->rcv_auth));
    memset(&(_stcpWI->rcv_cookies), 0x00, sizeof(_stcpWI->rcv_cookies));
    memset(&(_stcpWI->rcv_connection_type), 0x00, sizeof(_stcpWI->rcv_connection_type));

    _stcpWI->content_length = 0;
    _stcpWI->partial_length = 0;
}

/**
 * clear and free STCP Webserver Standard variable/parameters allocated memmory
 * @param[in] _stcpWI a pointer of __stcpWInfo__ (struct stcp_webserver_info)
 * @param[in] _stcpWH a pointer of __stcpHead__ (struct stcp_webserver_header)
 * @param[in] _stcpWList a pointer of __stcpWList__ (SHLink)
 * @return 0 if success or 1 if failed to allocate memmory (8 bit integer value)
 */
static void stcp_http_webserver_free(stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList *_stcpWList){
    free(_stcpWI->server_header);
    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "free server header success\n");
    free(_stcpWI->rcv_header);
    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "free receive header success\n");
    free(_stcpWI->rcv_content);
    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "free receive content success\n");
    free(_stcpWI->ipaddr);
    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "free ip adrress buffer success\n");
    free(_stcpWH->content_type);
    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "free content type success\n");
    free(_stcpWH->accept_type);
    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "free accept type success\n");

    _stcpWI->server_header = NULL;
    _stcpWI->rcv_header = NULL;
    _stcpWI->rcv_content = NULL;
    _stcpWI->content_length = 0;
    _stcpWI->rcv_content = NULL;
    _stcpWI->ipaddr = NULL;
    _stcpWH->content_type = NULL;
    _stcpWH->accept_type = NULL;

    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "try to free response list\n");
    shilink_free(_stcpWList);
    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "free response list success\n");
    *_stcpWList = NULL;
}

/**
 * get segmentation information of received header on STCP Webserver for specific HTTP Header field
 * @param[in] _source_text an unsigned char pointer of received header
 * @param[in] _specific_word a constant unsigned character pointer of keyword
 * @param[out] _pos an unsigned short pointer that will inform the start position of information that have been specified by keyword
 * @param[out] _size an unsigned short pointer that will inform the size of information that have been specified by keyword
 * @param[in] _end_code a constant unsigned character that inform the stop byte of the information (in HTTP, the suitable value for this field is __CR__)
 * @param[in] _mode 8 bit integer parameter for inform the function that _source_text parameter need to be lower case or not (set this field to 0 for disable lowercase options)
 */
static void stcp_http_webserver_header_segment(
 unsigned char *_source_text,
 const unsigned char *_specific_word,
 uint16_t *_pos,
 uint16_t *_size,
 const unsigned char _end_code,
 int8_t _mode
){
    size_t len_buff = strlen((const char *) _source_text);
    uint16_t idx_char = (uint16_t) (strlen((const char *) _specific_word) % UINT16_MAX);
    uint16_t content_size = 0;
    *_size = 0;
    if(memcmp(_source_text, _specific_word, idx_char) == 0 && len_buff-idx_char > 2){
		uint16_t i = 0;
        if (_source_text[idx_char] == 0x20){
            idx_char++;
        }
        *_pos += idx_char;
        for (i=idx_char; i<len_buff; i++){
            if(_source_text[i] != _end_code){
                if (_source_text[i] >= 'A' && _source_text[i] <= 'Z' && _mode){
                    _source_text[i] += 0x20;
                }
                content_size++;
            }
            else {
                break;
            }
        }
        *_size = content_size;
        return;
    }
    return;
}

/**
 * print segmentation information of received header on STCP Webserver for specific HTTP Header field that has been processed on stcp_http_webserver_header_segment function
 * @param[in] _header a constant unsigned character pointer of received header
 * @param[in] _segmen_data a constant stcp_subhead_var structure that inform the position and size of information
 * @param[in] _description a constant character pointer of debug descriptions (additional information)
 */
static inline void stcp_http_webserver_print_segment(
 const unsigned char *_header,
 const stcpSHead _segmen_data,
 const char *_description
){
    if (_segmen_data.stcp_sub_size == 0){
        stcp_debug(__func__, STCP_DEBUG_INFO, "%s: (null)\n", _description);
        return;
    }
    stcp_debug(__func__, STCP_DEBUG_INFO, "%s:\r\n", _description);
    if (stcp_setup_data.stcp_debug_mode == STCP_DEBUG_ON){
        write(STDOUT_FILENO, _header + _segmen_data.stcp_sub_pos, _segmen_data.stcp_sub_size);
        printf("\r\n");
    }
}

/**
 * get partial length information from received header in STCP Webserver
 * @param[in] _text_source a constant character pointer of received header
 * @return size of partial length (0 if partial length field not found)
 */
static unsigned long long stcp_get_partial_length(const char *_text_source){
    static char buff_info[17];
    static char buff_data[10];
    size_t i = 0;
    size_t source_length = strlen(_text_source);
    for (i=0; i<(source_length - 13); i++){
        memset(buff_info, 0x00, sizeof(buff_info));
        int8_t j=0;
        for (j=0; j<13; j++){
            buff_info[j] = _text_source[i + j];
        }
        if (strcmp(buff_info, "Range: bytes=") == 0){
            i = i + 13;
            memset(buff_data, 0x00, sizeof(buff_data));
            int8_t j = 0;
            for (j=0; j<9; j++){
                if (j>0 && (_text_source[i + j] < '0' || _text_source[i + j] > '9')){
                    return (unsigned long long) atoll(buff_data);
                }
                else if (_text_source[i + j] >= '0' && _text_source[i + j] <= '9'){
                    buff_data[j] = _text_source[i + j];
                }
            }
        }
    }
    return 0;
}

/**
 * Parsing information of received header on STCP Webserver to segmentation data form in _stcpWI parameters
 * @param[in, out] _stcpWI a pointer of __stcpWInfo__ (struct stcp_webserver_info)
 */
void stcp_http_webserver_header_parser(stcpWInfo *_stcpWI){
    uint16_t idx_char = 0;
    stcp_debug(__func__, STCP_DEBUG_INFO, "HEADER\n%s\n", (char *) _stcpWI->rcv_header);
    unsigned char *header_tmp = NULL;
    /* GET REQUEST TYPE */
    _stcpWI->request.stcp_sub_pos = 0;
    _stcpWI->request.stcp_sub_size = 0;
    while (_stcpWI->rcv_header[idx_char] != ' ' && _stcpWI->rcv_header[idx_char] != 0x00){
        idx_char++;
        _stcpWI->request.stcp_sub_size++;
    }
    idx_char++;
    stcp_http_webserver_print_segment(_stcpWI->rcv_header, _stcpWI->request, "REQUEST");
    /* GET ENDPOINT */
    _stcpWI->rcv_endpoint.stcp_sub_pos = idx_char;
    while (_stcpWI->rcv_header[idx_char] != ' ' &&
     _stcpWI->rcv_header[idx_char] != 0x00 && 
     _stcpWI->rcv_header[idx_char] != '?'
    ){
        idx_char++;
        _stcpWI->rcv_endpoint.stcp_sub_size++;
    }
    stcp_http_webserver_print_segment((unsigned char *) _stcpWI->rcv_header, _stcpWI->rcv_endpoint, "ENDPOINT");
    if (_stcpWI->rcv_header[idx_char] == '?'){
        idx_char++;
        _stcpWI->data_end_point.stcp_sub_pos = idx_char;
        _stcpWI->data_end_point.stcp_sub_size = 0;
        while (_stcpWI->rcv_header[idx_char] != ' ' &&
         _stcpWI->rcv_header[idx_char] != 0x00
        ){
            idx_char++;
            _stcpWI->data_end_point.stcp_sub_size++;
        }
    }
    stcp_http_webserver_print_segment(_stcpWI->rcv_header, _stcpWI->data_end_point, "DATA ENDPOINT");
    /* GET CONTENT TYPE */
    if ((header_tmp = (unsigned char *) strstr((char *) _stcpWI->rcv_header, "Content-Type:")) != NULL){
        _stcpWI->rcv_content_type.stcp_sub_pos = (uint16_t) ((header_tmp - _stcpWI->rcv_header) % UINT16_MAX);
        stcp_http_webserver_header_segment(
         header_tmp,
         (unsigned char *) "Content-Type:",
         &(_stcpWI->rcv_content_type.stcp_sub_pos),
         &(_stcpWI->rcv_content_type.stcp_sub_size),
         '\r',
         0x01);
    }
    stcp_http_webserver_print_segment((unsigned char *) _stcpWI->rcv_header, _stcpWI->rcv_content_type, "CONTENT TYPE");
    /* GET BOUNDARY */
    if ((header_tmp = (unsigned char *) strstr((char *) _stcpWI->rcv_header, "boundary=")) != NULL){
        _stcpWI->rcv_boundary.stcp_sub_pos = (uint16_t) ((header_tmp - _stcpWI->rcv_header) % UINT16_MAX);
        stcp_http_webserver_header_segment(
         header_tmp,
         (unsigned char *) "boundary=",
         &(_stcpWI->rcv_boundary.stcp_sub_pos),
         &(_stcpWI->rcv_boundary.stcp_sub_size),
         '\r',
         0x00);
    }
    stcp_http_webserver_print_segment(_stcpWI->rcv_header, _stcpWI->rcv_boundary, "BOUNDARY");
    /* GET CONNECTION TYPE */
    if ((header_tmp = (unsigned char *) strstr((char *) _stcpWI->rcv_header, "Connection:")) != NULL){
        _stcpWI->rcv_connection_type.stcp_sub_pos = (uint16_t) ((header_tmp - _stcpWI->rcv_header) % UINT16_MAX);
        stcp_http_webserver_header_segment(
         header_tmp,
         (unsigned char *) "Connection:",
         &(_stcpWI->rcv_connection_type.stcp_sub_pos),
         &(_stcpWI->rcv_connection_type.stcp_sub_size),
         '\r',
         0x01);
    }
    stcp_http_webserver_print_segment(_stcpWI->rcv_header, _stcpWI->rcv_connection_type, "CONNECTION");
    /* GET ACCEPTION TYPE */
    if ((header_tmp = (unsigned char *) strstr((char *) _stcpWI->rcv_header, "Accept:")) != NULL){
        _stcpWI->rcv_acception_type.stcp_sub_pos = (uint16_t) ((header_tmp - _stcpWI->rcv_header) % UINT16_MAX);
        stcp_http_webserver_header_segment(
         header_tmp,
         (unsigned char *) "Accept:",
         &(_stcpWI->rcv_acception_type.stcp_sub_pos),
         &(_stcpWI->rcv_acception_type.stcp_sub_size),
         '\r',
         0x01);
    }
    stcp_http_webserver_print_segment(_stcpWI->rcv_header, _stcpWI->rcv_acception_type, "ACCEPT");
    /* GET AUTH */
    if ((header_tmp = (unsigned char *) strstr((char *) _stcpWI->rcv_header, "Authentication:")) != NULL){
        _stcpWI->rcv_auth.stcp_sub_pos = (uint16_t) ((header_tmp - _stcpWI->rcv_header) % UINT16_MAX);
        stcp_http_webserver_header_segment(
         header_tmp,
         (unsigned char *) "Authentication:",
         &(_stcpWI->rcv_auth.stcp_sub_pos),
         &(_stcpWI->rcv_auth.stcp_sub_size),
         '\r',
         0x00);
    }
    else if ((header_tmp = (unsigned char *) strstr((char *) _stcpWI->rcv_header, "Authorization:")) != NULL){
        _stcpWI->rcv_auth.stcp_sub_pos = (uint16_t) ((header_tmp - _stcpWI->rcv_header) % UINT16_MAX);
        stcp_http_webserver_header_segment(
         header_tmp,
         (unsigned char *) "Authorization:",
         &(_stcpWI->rcv_auth.stcp_sub_pos),
         &(_stcpWI->rcv_auth.stcp_sub_size),
         '\r',
         0x00);
    }
    stcp_http_webserver_print_segment(_stcpWI->rcv_header, _stcpWI->rcv_auth, "AUTH");
    /* GET COOKIE */
    if ((header_tmp = (unsigned char *) strstr((char *) _stcpWI->rcv_header, "Cookie:")) != NULL){
        _stcpWI->rcv_cookies.stcp_sub_pos = (uint16_t) ((header_tmp - _stcpWI->rcv_header) % UINT16_MAX);
        stcp_http_webserver_header_segment(
         header_tmp,
         (unsigned char *) "Cookie:",
         &(_stcpWI->rcv_cookies.stcp_sub_pos),
         &(_stcpWI->rcv_cookies.stcp_sub_size),
         '\r',
         0x00);
    }
    stcp_http_webserver_print_segment(_stcpWI->rcv_header, _stcpWI->rcv_cookies, "COOKIE");
    /* GET CONTENT LENTH */
    _stcpWI->content_length = (uint32_t) stcp_get_content_length((char *) _stcpWI->rcv_header);

    stcp_debug(__func__, STCP_DEBUG_INFO, "CONTENT LENGTH: %i\n", _stcpWI->content_length);

    _stcpWI->partial_length = (uint64_t) stcp_get_partial_length((const char *) _stcpWI->rcv_header);

    stcp_debug(__func__, STCP_DEBUG_INFO, "PARTIAL LENGTH: %i\n", _stcpWI->partial_length);
}

/**
 * Parsing information of received header on STCP Webserver to segmentation data form in _stcpWI parameters
 * @param[in, out] _stcpWI a pointer of __stcpWInfo__ (header that have been generated will be stored in server_header, member of struct stcp_webserver_info)
 * @param[in] _response_header a constant character pointer of response code HTTP Header (example: 200 OK)
 * @param[in] _content_type a constant character pointer of content-type filed of HTTP Header (example: text/html, or can include another informations like connection separated by CR LF (example: "text/html\r\nconnection:close"))
 * @param[in] _acception_type _content_type a constant character pointer of Accept field of HTTP Header (example: text/html, or can include another informations like connection separated by CR LF (example: "text/html\r\nconnection:close"))
 * @param[in] _content_length an unsigned long long integer (64 bytes) parameters that inform the function length of HTTP Response Content
 * @return 0 if success
 */
int8_t stcp_http_webserver_generate_header(
 stcpWInfo *_stcpWI,
 const char *_response_header,
 const char *_content_type,
 const char *_acception_type,
 uint64_t _content_length
){
    time_t stcp_time_access = 0;
    struct tm tm_access;
    time(&stcp_time_access);
    memcpy(&tm_access, gmtime(&stcp_time_access), sizeof(tm_access));

    _stcpWI->server_header[0] = 0x00;
    _stcpWI->server_header = (char *) stcp_http_str_append(
     _stcpWI->server_header,
     128,
     0,
     "HTTP/1.1 %s\r\n"
     "Date: %s, %02d %s %04d %02d:%02d:%02d GMT\r\n"
     "Access-Control-Allow-Origin: *\r\n"
     "Content-Type: %s\r\n"
     "Server: stcp-webservice\r\n"
     "Accept: %s\r\n"
     "Vary: Accept-Encoding\r\n",
     _response_header,
     stcp_day_str[tm_access.tm_wday],
     tm_access.tm_mday,
     stcp_mon_str[tm_access.tm_mon],
     (tm_access.tm_year + 1900),
     tm_access.tm_hour,
     tm_access.tm_min,
     tm_access.tm_sec,
     _content_type,
     _acception_type
    );
    if (_content_length > 0) {
        if (memcmp(_stcpWI->rcv_header + _stcpWI->rcv_connection_type.stcp_sub_pos, "keep-alive", 10) == 0){
            _stcpWI->server_header = (char *) stcp_http_str_append(_stcpWI->server_header,
             (unsigned short) 32,
             (unsigned short) 0,
             "Content-Length: %li\r\n"
             "Connection: keep-alive\r\n"
             "\r\n",
             _content_length
            );
        }
        else {
            _stcpWI->server_header = (char *) stcp_http_str_append(_stcpWI->server_header,
             (unsigned short) 32,
             (unsigned short) 0,
             "Content-Length: %li\r\n\r\n",
             _content_length
            );
        }
    }
    else {
        _stcpWI->server_header = (char *) stcp_http_str_append(_stcpWI->server_header,
         (unsigned short) 32,
         (unsigned short) 26,
         "Transfer-Encoding: chunked\r\n"
         "Connection: close\r\n"
         "\r\n"
        );
    }
    return 0x00;
}

/**
 * Generated full response of HTTP Server (Header + content/body)
 * @param[in, out] _stcpWI a pointer of __stcpWInfo__ (header that have been generated will be stored in server_header, member of struct stcp_webserver_info)
 * @param[in] _response_header a constant character pointer of response code HTTP Header (example: 200 OK)
 * @param[in] _content_type a constant character pointer of content-type filed of HTTP Header (example: text/html, or can include another informations like connection separated by CR LF (example: "text/html\r\nconnection:close"))
 * @param[in] _acception_type _content_type a constant character pointer of Accept field of HTTP Header (example: text/html, or can include another informations like connection separated by CR LF (example: "text/html\r\nconnection:close"))
 * @param[in] _content_with_malloc an allocated character pointer memmory that inform content/body oh HTTP Server Response (will be free automatically in this function)
 * @return character pointer that stored response information if success, NULL if failed
 */
char *stcp_http_webserver_generate_full_response(
 stcpWInfo *_stcpWI,
 const char *_response_header,
 const char *_content_type,
 const char *_acception_type,
 char *_content_with_malloc /* memory allocation will be free by function */
){
    if (_content_with_malloc == NULL){
        return NULL;
    }
    uint64_t content_length_rsp = (uint64_t) strlen(_content_with_malloc);
    if (stcp_http_webserver_generate_header(
     _stcpWI,
     _response_header,
     _content_type,
     _acception_type,
     content_length_rsp
    )){
        return NULL;
    }
    char *result = stcp_http_content_generator(
     128,
     "%s"
     "%s",
     _stcpWI->server_header,
     _content_with_malloc
    );
    free(_content_with_malloc);
    _content_with_malloc = NULL;
    return result;
}

/**
 * Add negative respon code on HTTP Server Header on response list
 * @param[in, out] _stcpWList a pointer of __stcpWList__ (SHLink) that will be store all HTTP Server header
 * @param[in] _code_param a member of enum on __stcp_webserver_negative_code__ (you can find this on header file)
 * @param[in] _response_content a constant character pointer that inform the response content of selected negative code
 * @return 0 if success, 1 if _code_param is wrong, 2 if failed to add response
 */
int8_t stcp_http_webserver_add_negative_code_response(
 stcpWList *_stcpWList,
 stcp_webserver_negative_code _code_param,
 const char *_response_content
){
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
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "invalid parameters\n");
        #endif
        return 0x01;
    }
    if(shilink_fill_custom_data(
     &_data,
     (const void *) data_key,
     (uint16_t) strlen(data_key),
     (const void *) _response_content,
     (uint16_t) strlen(_response_content),
     SL_TEXT
    ) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (1)\n");
        #endif
        return 0x02;
    }
    if (shilink_append(_stcpWList, _data) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (2)\n");
        #endif
        shilink_free_custom_data(&_data);
        return 0x02;
    }
    return 0x00;
}

/**
 * Add text respon content of HTTP Server for specific request type (GET/POST/PATCH/etc) and specific endpoint on response list
 * @param[in, out] _stcpWList a pointer of __stcpWList__ (SHLink) that will be store all HTTP Server rensponse
 * @param[in] _end_point a constant character pointer of HTTP endpoint
 * @param[in] _response_content a constant character pointer that inform the response content of selected endpoint
 * @param[in] _request_method a constant character pointer of HTTP Request Method (GET/POST/PATCH/etc)
 * @return 0 if success, 1 if _code_param is wrong
 */
int8_t stcp_http_webserver_add_response(
 stcpWList *_stcpWList,
 const char *_end_point,
 const char *_response_content,
 const char *_request_method
){
    SHLinkCustomData _data;
    char data_key[strlen(_end_point) + strlen(_request_method) + 1];
    memset(data_key, 0x00, sizeof(data_key));
    sprintf(data_key, "%s%s", _request_method, _end_point);
    if(shilink_fill_custom_data(
     &_data,
     (const void *) data_key,
     (uint16_t) strlen(data_key),
     (const void *) _response_content,
     (uint16_t) strlen(_response_content),
     SL_TEXT
    ) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (1)\n");
        #endif
        return 0x01;
    }
    if (shilink_append(_stcpWList, _data) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (2)\n");
        #endif
        shilink_free_custom_data(&_data);
        return 0x01;
    }
    return 0x00;
}

/**
 * Add file as respon content of HTTP Server for specific request type (GET/POST/PATCH/etc) and specific endpoint on response list
 * @param[in, out] _stcpWList a pointer of __stcpWList__ (SHLink) that will be store all HTTP Server rensponse
 * @param[in] _end_point a constant character pointer of HTTP endpoint
 * @param[in] _response_file a constant character pointer that inform the response file location
 * @param[in] _request_method a constant character pointer of HTTP Request Method (GET/POST/PATCH/etc)
 * @return 0 if success, 1 if _code_param is wrong
 */
int8_t stcp_http_webserver_add_response_file(
 stcpWList *_stcpWList,
 const char *_end_point,
 const char *_response_file,
 const char *_request_method
){
    SHLinkCustomData _data;
    char data_key[strlen(_end_point) + strlen(_request_method) + 1];
    char data_value[strlen(_response_file) + 11];
    memset(data_key, 0x00, sizeof(data_key));
    memset(data_value, 0x00, sizeof(data_value));
    sprintf(data_key, "%s%s", _request_method, _end_point);
    sprintf(data_value, "open_file:%s", _response_file);
    if(shilink_fill_custom_data(
     &_data,
     (const void *) data_key,
     (uint16_t) strlen(data_key),
     (const void *) data_value,
     (uint16_t) strlen(data_value),
     SL_TEXT
    ) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (1)\n");
        #endif
        return 0x01;
    }
    if (shilink_append(_stcpWList, _data) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (2)\n");
        #endif
        shilink_free_custom_data(&_data);
        return 0x01;
    }
    return 0x00;
}

/**
 * Add directory and all of its content as respon content of HTTP Server for specific request type (GET/POST/PATCH/etc) and specific endpoint on response list
 * @param[in, out] _stcpWList a pointer of __stcpWList__ (SHLink) that will be store all HTTP Server rensponse
 * @param[in] _base_end_point a constant character pointer of HTTP base endpoint
 * @param[in] _response_directory a constant character pointer that inform the response directory location
 * @param[in] _request_method a constant character pointer of HTTP Request Method (GET/POST/PATCH/etc)
 * @return 0 if success, 1 if _code_param is wrong
 */
int8_t stcp_http_webserver_add_response_directory(
 stcpWList *_stcpWList,
 const char *_base_end_point,
 const char *_response_directory,
 const char *_request_method
){
    DIR *directory = NULL;
    char *storageList = NULL;
    struct dirent *enDirTmp = NULL;
    struct dirent enDir;
    long dCount = 0;

    directory = opendir(_response_directory);
    if (directory == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response directory (0) \"%s\"\n", _response_directory);
        #endif
        return 0x01;
    }
    storageList = (char *) malloc(2 * sizeof(char));
    memset(storageList, 0x00, 2 * sizeof(char));
    if (storageList == NULL){
        closedir(directory);
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response directory (0) \"%s\"\n", _response_directory);
        #endif
        return 0x01;
    }

    do {
        enDirTmp = readdir(directory);
        if (enDirTmp == NULL){
            break;
        }
        memcpy(&enDir, enDirTmp, sizeof(enDir));
        if (enDir.d_type == DT_DIR){
            if (enDir.d_name[0] != '.'){
                if (storageList[0] != 0x00){
                    storageList = stcp_http_str_append(
                     storageList,
                     8,
                     0,
                     ",\n    \"d%li\":\"%s\"",
                     dCount,
                     enDir.d_name
                    );
                }
                else {
                    storageList = stcp_http_str_append(
                     storageList,
                     8,
                     0,
                     "{\n    \"d%li\":\"%s\"",
                     dCount,
                     enDir.d_name
                    );
                }
                char dnameTmp[strlen(enDir.d_name) + strlen(_response_directory) + 2];
                memset(dnameTmp, 0x00, sizeof(dnameTmp));
                sprintf(dnameTmp, "%s/%s", _response_directory, enDir.d_name);
                stcp_http_webserver_add_response_directory(
                 _stcpWList,
                 _base_end_point,
                 dnameTmp,
                 _request_method
                );
                dCount++;
            }
        }
        else if (enDir.d_type == DT_REG){
            if (storageList[0] != 0x00){
                storageList = stcp_http_str_append(
                 storageList,
                 8,
                 0,
                 ",\n    \"d%li\":\"%s\"",
                 dCount,
                 enDir.d_name
                );
            }
            else {
                storageList = stcp_http_str_append(
                 storageList,
                 8,
                 0,
                 "{\n    \"d%li\":\"%s\"",
                 dCount,
                 enDir.d_name
                );
            }
            char fnameTmp[strlen(enDir.d_name) + strlen(_response_directory) + strlen(_base_end_point) + 3];
            memset(fnameTmp, 0x00, sizeof(fnameTmp));
            sprintf(fnameTmp, "%s/%s/%s", _base_end_point, _response_directory, enDir.d_name);
            stcp_http_webserver_add_response_file(
             _stcpWList,
             fnameTmp,
             fnameTmp + strlen(_base_end_point) + 1,
             _request_method
            );
            dCount++;
        }
    } while (1);

    if (storageList[0] == 0){
        storageList = stcp_http_str_append(
         storageList,
         8,
         0,
         "{\"n%li\":\"none\"}",
         dCount
        );
    }
    else {
        storageList = stcp_http_str_append(
         storageList,
         8,
         6,
         "\n}\r\n\r\n"
        );
    }
    char dnameTmp[strlen(_response_directory) + strlen(_base_end_point) + 2];
    memset(dnameTmp, 0x00, sizeof(dnameTmp));
    sprintf(dnameTmp, "%s/%s", _base_end_point, _response_directory);
    stcp_http_webserver_add_response(
     _stcpWList,
     dnameTmp,
     storageList,
     _request_method
    );
    free(storageList);
    storageList = NULL;

    closedir(directory);
    directory = NULL;
    return 0;    
}

/**
 * Add callback function as respon content of HTTP Server for specific request type (GET/POST/PATCH/etc) and specific endpoint on response list
 * @param[in, out] _stcpWList a pointer of __stcpWList__ (SHLink) that will be store all HTTP Server rensponse
 * @param[in] _end_point a constant character pointer of HTTP endpoint
 * @param[in] _response_function a constant void pointer of function (function format example: void *webservice_callback_example(stcpSock _init_data, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList _stcpWList, int8_t *_retval))
 * @param[in] _request_method a constant character pointer of HTTP Request Method (GET/POST/PATCH/etc)
 * @return 0 if success, 1 if _code_param is wrong
 */
int8_t stcp_http_webserver_add_response_callback(
 stcpWList *_stcpWList,
 const char *_end_point,
 const void *_response_function,
 const char *_request_method
){
    SHLinkCustomData _data;
    char data_key[strlen(_end_point) + strlen(_request_method) + 1];
    char data_value[10 + sizeof(void *)];
    memset(data_key, 0x00, sizeof(data_key));
    memset(data_value, 0x00, sizeof(data_value));
    sprintf(data_key, "%s%s", _request_method, _end_point);
    memcpy(data_value, "callback:", 9);
    memcpy(data_value + 9, &_response_function, sizeof(void *));
    if(shilink_fill_custom_data(
     &_data,
     (const void *) data_key,
     (uint16_t) strlen(data_key),
     (const void *) data_value,
     (uint16_t) (9 + sizeof(void *)),
     SL_TEXT
    ) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (1)\n");
        #endif
        return 0x01;
    }
    if (shilink_append(_stcpWList, _data) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (2)\n");
        #endif
        shilink_free_custom_data(&_data);
        return 0x01;
    }
    return 0x00;
}

/**
 * Add callback function as respon content of TCP/IP Server in STCP Webserver for specific request type (GET/POST/PATCH/etc) and specific endpoint on response list
 * @param[in, out] _stcpWList a pointer of __stcpWList__ (SHLink) that will be store all HTTP Server rensponse
 * @param[in] _start_bits a constant unsigned character pointer of TCP/IP received data start bits
 * @param[in] _start_bits_size an unsigned short that inform size of start bits
 * @param[in] _response_function a constant void pointer of function (function format example: void *webservice_callback_example(stcpSock _init_data, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList _stcpWList, int8_t *_retval))
 * @return 0 if success, 1 if _code_param is wrong
 */
int8_t stcp_http_webserver_add_tcp_response_callback(
 stcpWList *_stcpWList,
 const unsigned char *_start_bits,
 uint16_t _start_bits_size,
 const void *_response_function
){
    SHLinkCustomData _data;
    char data_value[10 + sizeof(void *)];
    memset(data_value, 0x00, sizeof(data_value));
    memcpy(data_value, "tcp_call:", 9);
    memcpy(data_value + 9, &_response_function, sizeof(void *));
    if(shilink_fill_custom_data(
     &_data,
     (const void *) _start_bits,
     _start_bits_size,
     (const void *) data_value,
     (uint16_t) (9 + sizeof(void *)),
     SL_TEXT
    ) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (1)\n");
        #endif
        return 0x01;
    }
    if (shilink_append(_stcpWList, _data) != 0){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to add response (2)\n");
        #endif
        shilink_free_custom_data(&_data);
        return 0x01;
    }
    return 0x00;
}

/**
 * Get response from received request of STCP Webserver
 * @param[in] _stcpWI  a pointer of __stcpWInfo__ (struct stcp_webserver_info) that store all information of received data
 * @param[in] _stcpWList a pointer of __stcpWList__ (SHLink) that store all of HTTP Server rensponse
 * @param[out] _respons_code a character pointer that will be store response code of HTTP Server Header (example: 200 OK)
 * @return unsigned char pointer of response if success, NULL if response not found
 */
unsigned char *stcp_http_webserver_select_response(
 stcpWInfo *_stcpWI,
 stcpWList _stcpWList,
 char *_respons_code
){
    SHLinkCustomData _data;

    char data_key[_stcpWI->request.stcp_sub_size + _stcpWI->rcv_endpoint.stcp_sub_size + 8];
    memset(data_key, 0x00, sizeof(data_key));
    memcpy(data_key,
     _stcpWI->rcv_header + _stcpWI->request.stcp_sub_pos,
     _stcpWI->request.stcp_sub_size
    );
    memcpy(data_key + _stcpWI->request.stcp_sub_size,
     _stcpWI->rcv_header + _stcpWI->rcv_endpoint.stcp_sub_pos,
     _stcpWI->rcv_endpoint.stcp_sub_size);
    
    if (shilink_search_data_by_position(
     _stcpWList,
     (const void *) data_key,
     (uint16_t) strlen(data_key),
     0,
     &_data
    ) != 0){
        if (memcmp("GET",
         _stcpWI->rcv_header + _stcpWI->request.stcp_sub_pos,
         _stcpWI->request.stcp_sub_size
        ) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            memcpy(data_key, "GET", 3);
            memcpy(data_key + 3,
             _stcpWI->rcv_header + _stcpWI->rcv_endpoint.stcp_sub_pos,
             _stcpWI->rcv_endpoint.stcp_sub_size);
            if (shilink_search_data_by_position(
             _stcpWList,
             (const void *) data_key,
             (uint16_t) strlen(data_key),
             0,
             &_data
            ) == 0){
                goto next405;
            }
        }
        if (memcmp("POST",
         _stcpWI->rcv_header + _stcpWI->request.stcp_sub_pos,
         _stcpWI->request.stcp_sub_size
        ) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            memcpy(data_key, "POST", 4);
            memcpy(data_key + 4,
             _stcpWI->rcv_header + _stcpWI->rcv_endpoint.stcp_sub_pos,
             _stcpWI->rcv_endpoint.stcp_sub_size);
            if (shilink_search_data_by_position(
             _stcpWList,
             (const void *) data_key,
             (uint16_t) strlen(data_key),
             0,
             &_data
            ) == 0){
                goto next405;
            }
        }
        if (memcmp("PUT",
         _stcpWI->rcv_header + _stcpWI->request.stcp_sub_pos,
         _stcpWI->request.stcp_sub_size
        ) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            memcpy(data_key, "PUT", 3);
            memcpy(data_key + 3,
             _stcpWI->rcv_header + _stcpWI->rcv_endpoint.stcp_sub_pos,
             _stcpWI->rcv_endpoint.stcp_sub_size);
            if (shilink_search_data_by_position(
             _stcpWList,
             (const void *) data_key,
             (uint16_t) strlen(data_key),
             0,
             &_data
            ) == 0){
                goto next405;
            }
        }
        if (memcmp("HEAD",
         _stcpWI->rcv_header + _stcpWI->request.stcp_sub_pos,
         _stcpWI->request.stcp_sub_size
        ) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            memcpy(data_key, "HEAD", 4);
            memcpy(data_key + 4,
             _stcpWI->rcv_header + _stcpWI->rcv_endpoint.stcp_sub_pos,
             _stcpWI->rcv_endpoint.stcp_sub_size);
            if (shilink_search_data_by_position(
             _stcpWList,
             (const void *) data_key,
             (uint16_t) strlen(data_key),
             0,
             &_data
            ) == 0){
                goto next405;
            }
        }
        if (memcmp("DELETE",
         _stcpWI->rcv_header + _stcpWI->request.stcp_sub_pos,
         _stcpWI->request.stcp_sub_size
        ) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            memcpy(data_key, "DELETE", 6);
            memcpy(data_key + 6,
             _stcpWI->rcv_header + _stcpWI->rcv_endpoint.stcp_sub_pos,
             _stcpWI->rcv_endpoint.stcp_sub_size);
            if (shilink_search_data_by_position(
             _stcpWList,
             (const void *) data_key,
             (uint16_t) strlen(data_key),
             0,
             &_data
            ) == 0){
                goto next405;
            }
        }
        if (memcmp("PATCH",
         _stcpWI->rcv_header + _stcpWI->request.stcp_sub_pos,
         _stcpWI->request.stcp_sub_size
        ) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            memcpy(data_key, "PATCH", 5);
            memcpy(data_key + 5,
             _stcpWI->rcv_header + _stcpWI->rcv_endpoint.stcp_sub_pos,
             _stcpWI->rcv_endpoint.stcp_sub_size);
            if (shilink_search_data_by_position(
             _stcpWList,
             (const void *) data_key,
             (uint16_t) strlen(data_key),
             0,
             &_data
            ) == 0){
                goto next405;
            }
        }
        if (memcmp("OPTIONS",
         _stcpWI->rcv_header + _stcpWI->request.stcp_sub_pos,
         _stcpWI->request.stcp_sub_size
        ) != 0){
            memset(data_key, 0x00, sizeof(data_key));
            memcpy(data_key, "OPTIONS", 7);
            memcpy(data_key + 7,
             _stcpWI->rcv_header + _stcpWI->rcv_endpoint.stcp_sub_pos,
             _stcpWI->rcv_endpoint.stcp_sub_size);
            if (shilink_search_data_by_position(
             _stcpWList,
             (const void *) data_key,
             (uint16_t) strlen(data_key),
             0,
             &_data
            ) == 0){
                goto next405;
            }
        }
        strcpy(_respons_code, "404 Not Found");
        if (shilink_search_data_by_position(_stcpWList, "404", 3, 0, &_data) != 0){
            return NULL;
        }
        return (unsigned char *) _data.sl_value;
        
        next405 :
            strcpy(_respons_code, "405 Method Not Allowed");
            if (shilink_search_data_by_position(_stcpWList, "405", 3, 0, &_data) != 0){
                return NULL;
            }
            return (unsigned char *) _data.sl_value;
    }
    strcpy(_respons_code, "200 OK");
    if (memcmp(_data.sl_value, "callback:", 9) != 0){
        stcp_debug(__func__, STCP_DEBUG_INFO, "selected response: %s\n", (char *) _data.sl_value);
    }
    else {
        stcp_debug(__func__, STCP_DEBUG_INFO, "selected response: callback function\n");
    }
    return (unsigned char *) _data.sl_value;
}

/**
 * Get response from received request of STCP Webserver (specific for TCP/IP data)
 * @param[in] _tcp_received  an unsigned char pointer of received data
 * @param[in] _stcpWList a pointer of __stcpWList__ (SHLink) that store all of HTTP Server rensponse
 * @return unsigned char pointer of response if success, NULL if response not found
 */
unsigned char *stcp_http_webserver_select_tcp_response(unsigned char *_tcp_received, stcpWList _stcpWList){
    stcpWList response_list = _stcpWList;
    while (response_list != NULL){
        if(memcmp(response_list->sl_data.sl_value, (void *) "tcp_call:", 9) == 0){
            if (memcmp(response_list->sl_data.sl_key, (void *) _tcp_received, response_list->sl_data.sl_keysize) == 0){
                return (unsigned char *) response_list->sl_data.sl_value;
            }
        }
        response_list = response_list->sh_next;
    }
    return NULL;
}

/**
 * Set default content-type of STCP Webserver Header
 * @param[in] _stcpWH a pointer of __stcpHead__ (struct stcp_webserver_header)
 * @param[in] _content_type a constant char pointer of content-type will be set as default
 * @return 0 if success
 */
int8_t stcp_http_webserver_set_content_type(
 stcpWHead *_stcpWH,
 const char *_content_type
){
    _stcpWH->content_type = (char *) realloc(_stcpWH->content_type, (strlen(_content_type) + 1)*sizeof(char));
    strcpy(_stcpWH->content_type, _content_type);
    return 0x00;
}

/**
 * Set default Accept field of STCP Webserver Header
 * @param[in] _stcpWH a pointer of __stcpHead__ (struct stcp_webserver_header)
 * @param[in] _accept a constant char pointer of Accept field will be set as default
 * @return 0 if success
 */
int8_t stcp_http_webserver_set_accept(
 stcpWHead *_stcpWH,
 const char *_accept
){
    _stcpWH->accept_type = (char *) realloc(_stcpWH->accept_type, (strlen(_accept) + 1)*sizeof(char));
    strcpy(_stcpWH->accept_type, _accept);
    return 0x00;
}

/**
 * Send file as response of STCP Webserver (header has been included)
 * @param[in] _init_data socket informations that stored as stcpSock structure
 * @param[in] _stcpWI a pointer of __stcpWInfo__ (struct stcp_webserver_info)
 * @param[in] _stcpWH a pointer of __stcpHead__ (struct stcp_webserver_header)
 * @param[in] _response_code a constant character pointer of HTTP Server response code (example: 200 OK)
 * @param[in] _file_name a constant character pointer of file path that will be send as response
 * @return 0 if success, -1 if failed to generate header, -2 if file not found, -3 if failed to allocate memory as file buffer (8 bit integer value)
 */
int8_t stcp_http_webserver_send_file(
 stcpSock _init_data,
 stcpWInfo *_stcpWI,
 stcpWHead *_stcpWH,
 const char *_response_code,
 const char *_file_name
){
    #ifdef __STCP_DEBUG__
    stcp_debug(__func__, STCP_DEBUG_INFO, "file name: %s\n", _file_name);
    #endif
    FILE *stcp_file = NULL;
    uint8_t try_times = 3;

    do{
    	stcp_file = fopen(_file_name, "rb");
        try_times--;
    } while (stcp_file == NULL && try_times > 0);

    if (stcp_file == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to open \"%s\"\n", _file_name);
        #endif
        if (stcp_http_webserver_generate_header(
         _stcpWI,
         _response_code,
         _stcpWH->content_type,
         _stcpWH->accept_type,
         11) != 0
        ){
            return (int8_t) -1;
        }
        char *buffer_info;

        buffer_info = stcp_http_content_generator(
         32,
         "%snot found!\n", _stcpWI->server_header
        );
        if (buffer_info == NULL){
            #ifdef __STCP_DEBUG__
            stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to generate webserver content\n");
            #endif
            return (int8_t) -1;
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
        return (int8_t) -2;
    }

    uint64_t content_size = 0;
    int8_t closed_flag = 0x00;
    fseek(stcp_file, 0L, SEEK_END);
    content_size = (uint64_t) ftell(stcp_file);

    if (_stcpWI->partial_length > 0){
        fseek(stcp_file, (long) _stcpWI->partial_length, SEEK_SET);
    }
    else {
        fseek(stcp_file, 0L, SEEK_SET);
    }

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
    else if (strstr(_file_name, ".png") != NULL){
        strcpy(content_type_file, "image/png");
    }
    else if (strstr(_file_name, ".jpg") != NULL){
        strcpy(content_type_file, "image/jpg");
    }
    else if (strstr(_file_name, ".jpeg") != NULL){
        strcpy(content_type_file, "image/jpeg");
    }
    else if (strstr(_file_name, ".bmp") != NULL){
        strcpy(content_type_file, "image/bmp");
    }
    else {
        strcpy(content_type_file, _stcpWH->content_type);
    }

    if (strstr((char *) _stcpWI->rcv_header, "Range: bytes=") == NULL){
        if (stcp_http_webserver_generate_header(
         _stcpWI,
         _response_code,
         content_type_file,
         _stcpWH->accept_type,
         content_size) != 0
        ){
            fclose(stcp_file);
            stcp_file = NULL;
            return (int8_t) -1;
        }
    }
    else {
        uint64_t partial_size = 1024000;
        char spc_buff[64];
        memset(spc_buff, 0x00, sizeof(spc_buff));
        if (content_size - _stcpWI->partial_length < partial_size){
            partial_size = content_size - _stcpWI->partial_length;
            closed_flag = (int8_t) -1;
        }
        sprintf(spc_buff, "*/*\r\n"
         "Content-Range: bytes %li-%li/%li",
         (long) _stcpWI->partial_length,
         (long) (_stcpWI->partial_length + partial_size - 1),
         (long) content_size
        );
        content_size = partial_size;
        if (stcp_http_webserver_generate_header(
         _stcpWI,
         "206 Partial Content",
         content_type_file,
         spc_buff,
         content_size) != 0
        ){
            fclose(stcp_file);
            stcp_file = NULL;
            return (int8_t) -1;
        }
    }

    if (!_stcpWI->comm_protocol){
        stcp_send_data(_init_data, (unsigned char *) _stcpWI->server_header, strlen(_stcpWI->server_header));
    }
    else {
        #ifdef __STCP_SSL__
            stcp_ssl_send_data(_init_data, (unsigned char *) _stcpWI->server_header, strlen(_stcpWI->server_header));
        #endif
    }

    unsigned char *file_content = NULL;
    file_content = (unsigned char *) malloc(stcp_setup_data.stcp_size_per_send * sizeof(char));
    if (file_content == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate memory for file_content\n");
        #endif
        fclose(stcp_file);
        stcp_file = NULL;
        return (int8_t) -3;
    }

    uint32_t size_recv = 0;
    size_t bytes = 0;
    uint64_t total_size = 0;
    unsigned char buff[2];
    while((bytes = fread((unsigned char *) buff, 1, 1, stcp_file) >= 0)){
		total_size = total_size + 1;
        file_content[size_recv] = buff[0];
        size_recv = size_recv + 1;
        if (size_recv == (stcp_setup_data.stcp_size_per_send * sizeof(char)) - 1 || bytes == 0){
            if (!_stcpWI->comm_protocol){
                if (stcp_send_data(_init_data, file_content, size_recv) <= 0){
                    closed_flag = (int8_t) -1;
                    break;
                }
            }
            else {
                #ifdef __STCP_SSL__
                    if (stcp_ssl_send_data(_init_data, file_content, size_recv) <= 0){
                        closed_flag = (int8_t) -1;
                        break;
                    }
                #else
                    closed_flag = (int8_t) -1;
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
                        closed_flag = (int8_t) -1;
                        break;
                    }
                }
                else {
                    #ifdef __STCP_SSL__
                        if (stcp_ssl_send_data(_init_data, file_content, size_recv) <= 0){
                            closed_flag = (int8_t) -1;
                            break;
                        }
                    #else
                        closed_flag = (int8_t) -1;
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
    return closed_flag;
}

/**
 * Main Callback Function of STCP Webserver response
 * @param[in] _init_data socket informations
 * @param[in] _function function that will be executed by Callback Function
 * @param[in] _stcpWI a pointer of __stcpWInfo__ (struct stcp_webserver_info)
 * @param[in] _stcpWH a pointer of __stcpHead__ (struct stcp_webserver_header)
 * @param[in] _stcpWList a pointer of __stcpWList__ (SHLink)
 * @return return of function that executed by Callback Function (return pass by *_retval parameter)
 */
static int8_t stcp_http_webserver_callback(
 stcpSock _init_data,
 const void *_function (stcpSock, stcpWInfo *, stcpWHead *, stcpWList, int8_t *),
 stcpWInfo *_stcpWI,
 stcpWHead *_stcpWH,
 stcpWList _stcpWList
){
    int8_t retval = (int8_t) -1;
    (*_function) (_init_data, _stcpWI, _stcpWH, _stcpWList, &retval);
    return retval;
}

/**
 * Start STCP Webserver
 * @param[in] ADDRESS a constant character pointer that inform the host address (example: 0.0.0.0)
 * @param[in] PORT an unsigned short that inform server port
 * @param[in] MAX_CLIENT an unsigned short that inform the maximum client can be accept by server at the same time
 * @param[in] _stcpWI a pointer of __stcpWInfo__ (struct stcp_webserver_info)
 * @param[in] _stcpWH a pointer of __stcpHead__ (struct stcp_webserver_header)
 * @param[in] _stcpWList a pointer of __stcpWList__ (SHLink)
 * @return some value if webserver terminated
 */
int8_t stcp_http_webserver(
 const char *ADDRESS,
 uint16_t PORT,
 uint16_t MAX_CLIENT,
 stcpWInfo *_stcpWI,
 stcpWHead *_stcpWH,
 stcpWList _stcpWList
){
    if (stcp_webserver_init_state == 0){
        stcp_debug(__func__, STCP_DEBUG_ERROR, "web server not ready\n");
        return 0x01;
    }

    /* check address & protocol*/
    /* 0 for http and 1 for https */
    _stcpWI->comm_protocol = 0;

    char *used_address = NULL;
    used_address = (char *) malloc((strlen(ADDRESS) + 1) * sizeof(char));
    if (used_address == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate address memory\n");
        #endif
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        return 0x01;
    }

    memset(used_address, 0x00, (strlen(ADDRESS) + 1) * sizeof(char));
    if (strstr(ADDRESS, "http://") != NULL){
        memcpy(used_address, ADDRESS + 7, strlen(ADDRESS) - 7);
    }
    else if (strstr(ADDRESS, "https://") != NULL){
        memcpy(used_address, ADDRESS + 8, strlen(ADDRESS) - 8);
        _stcpWI->comm_protocol = 1;
        #ifndef __STCP_SSL__
            stcp_debug(__func__, STCP_DEBUG_ERROR, "please define __STCP_SSL__ first\n");
            stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
            return 0x01;
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
    init_data.socket_f = 0;
    init_data.connection_f = 0;
    #ifdef __STCP_SSL__
        init_data.ssl_connection_f = NULL;
    #endif
    fd_set readfds;

    unsigned char *buffer = NULL;
    uint32_t buffer_size = stcp_setup_data.stcp_size_per_recv;
    buffer = (unsigned char *) malloc(buffer_size * sizeof(unsigned char));
    if (buffer == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate memory\n");
        #endif
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        free(used_address);
        used_address = NULL;
        init_data.socket_f = -1;
        return 0x01;
    }
    socklen_t len;
    struct sockaddr_in servaddr, cli;
    init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
    if (init_data.socket_f == -1) {
        stcp_debug(__func__, STCP_DEBUG_CRITICAL, "socket creation failed...\n");
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        free(used_address);
        free(buffer);
        used_address = NULL;
        buffer = NULL;
        return 0x00;
    }
    stcp_debug(__func__, STCP_DEBUG_INFO, "Socket successfully created : %d\n", init_data.socket_f);
    memset(&servaddr, 0x00, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = (in_port_t) htons(PORT);
    if(stcp_check_ip(used_address) != 0){
        struct hostent *host = NULL;
        host = gethostbyname(used_address);
        if (host != NULL){
            servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
        }
        else {
            #ifdef __STCP_DEBUG__
            stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to get host by name\n", used_address);
            #endif
            close(init_data.socket_f);
            init_data.socket_f = -1;
            stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
            free(used_address);
            free(buffer);
            used_address = NULL;
            buffer = NULL;
            return 0x02;
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
        stcp_debug(__func__, STCP_DEBUG_CRITICAL, "socket bind failed...\n");
        close(init_data.socket_f);
        init_data.socket_f = 0;
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        free(buffer);
        buffer = NULL;
        return 0x02;
    }
    stcp_debug(__func__, STCP_DEBUG_INFO, "Socket successfully binded..\n");
    if ((listen(init_data.socket_f, (int) MAX_CLIENT)) != 0) { 
        stcp_debug(__func__, STCP_DEBUG_CRITICAL, "Listen failed...\n");
        close(init_data.socket_f);
        init_data.socket_f = 0;
        stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
        free(buffer);
        buffer = NULL;
        return 0x02;
    }
    if (!_stcpWI->comm_protocol){
        stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "Server listening..\n"); 
    }
    else {
        #ifdef __STCP_SSL__
            ssl_ctx = NULL;
            #ifdef SSLv23_server_method
                ssl_ctx = SSL_CTX_new (SSLv23_server_method ());
            #else
                ssl_ctx = SSL_CTX_new (TLSv1_2_server_method ());
            #endif

            if (ssl_ctx == NULL){
                stcp_debug(__func__, STCP_DEBUG_WARNING, "unable to create new SSL context structure\n");
            }
            //#if !defined __XTENSA__ && !defined ESP_PLATFORM
            unsigned char* sslCertKey = NULL;
            stcp_ssl_certkey_type certkeyType = STCP_SSL_CACERT_TYPE_FILE;
            sslCertKey = stcp_ssl_get_cert(ADDRESS, &certkeyType);
            if (sslCertKey != NULL){
                if (certkeyType == STCP_SSL_CERT_TYPE_FILE){
                    if (SSL_CTX_use_certificate_file(ssl_ctx, (const char *) sslCertKey, SSL_FILETYPE_PEM) <= 0)
                    {
                        stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to open certificate file\n");
                    }
                }
                else {
                    X509 *tmpCertKey = stcp_ssl_create_cert_from_text(sslCertKey);
                    if (SSL_CTX_use_certificate(ssl_ctx, tmpCertKey) <= 0)
                    {
                        stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to add certificate\n");
                    }
                    if (tmpCertKey != NULL){
                        X509_free(tmpCertKey);
                    }
                }
            }
            sslCertKey = NULL;
            sslCertKey = stcp_ssl_get_key(ADDRESS, &certkeyType);
            if (sslCertKey != NULL){
                if (certkeyType == STCP_SSL_KEY_TYPE_FILE){
                    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, (const char *) sslCertKey, SSL_FILETYPE_PEM) <= 0)
                    {
                        stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to open private key file\n");
                    }
                }
                else {
                    RSA *tmpCertKey = stcp_ssl_create_key_from_text(sslCertKey);
                    if (SSL_CTX_use_RSAPrivateKey(ssl_ctx, tmpCertKey) <= 0)
                    {
                        stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to add privat key\n");
                    }
                    if (tmpCertKey != NULL){
                        RSA_free(tmpCertKey);
                    }
                }
                if (!SSL_CTX_check_private_key(ssl_ctx))
                {
                    stcp_debug(__func__, STCP_DEBUG_WARNING, "Private key does not match the public certificate\n");
                }
            }
            if(stcp_webserver_setup_data.stcp_sslw_verify_mode == STCP_SSL_WEBSERVER_VERIFY_REMOTE_CLIENT){
                sslCertKey = NULL;
                sslCertKey = stcp_ssl_get_cacert(ADDRESS, &certkeyType);
                if (sslCertKey != NULL){
                    if (certkeyType == STCP_SSL_CACERT_TYPE_FILE){
                        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
                        if (SSL_CTX_load_verify_locations(ssl_ctx, (const char *) sslCertKey, NULL) < 1)
                        {
                            stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to set verify location\n");
                        }
                    }
                    else {
                        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
                        if (SSL_CTX_load_verify_locations(ssl_ctx, (const char *) sslCertKey, NULL) < 1)
                        {
                            stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to set verify location\n");
                        }
                    }
                }
                else {
                    stcp_debug(__func__, STCP_DEBUG_WARNING, "CA cert not set\n");
                }
            }
            else {
                SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
            }
            //#endif
        #endif
        stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "Server https listening..\n");
    }

    len = sizeof(cli);

    int client_fd[MAX_CLIENT];
    struct in_addr client_addr[MAX_CLIENT];
    uint16_t keep_alive_cnt[MAX_CLIENT];
    #ifdef __STCP_SSL__
        SSL *ssl_client_fd[MAX_CLIENT];
    #endif
    struct timeval tv_timer;

    memset(client_fd, 0x00, sizeof(client_fd));
    memset(&client_addr, 0x00, sizeof(client_addr));
    memset(keep_alive_cnt, 0x00, sizeof(keep_alive_cnt));
    memset(buffer, 0x00, buffer_size*sizeof(unsigned char));

    int32_t stcp_bytes = 0;
    uint32_t stcp_size = 8;
    uint32_t idx_chr = 0;
    uint16_t max_sd = 0;
    uint16_t idx_client = 0;
    int16_t activity = 0;
    int8_t proc_state = STCP_PROCESS_GET_HEADER;
    stcp_server_state = STCP_SERVER_RUNING;
    unsigned char *response_content = NULL;
    void* _func_tmp = NULL;
    char *buffer_info = NULL;

    time_t elapsed_connection_counter = 0;
    struct slow_http_attack_var {
        time_t shat_timer;
        uint8_t shat_counter;
        struct in_addr shat_addr_record[8];
        time_t shat_time_record[8];
        uint8_t shat_counter_record[8];
    } slow_http_attack_handler;
    uint8_t idx_shat = 0;
    memset(&slow_http_attack_handler, 0x00, sizeof(slow_http_attack_handler));
    #ifdef __STCP_SSL__
        for (idx_client = 0; idx_client < MAX_CLIENT; idx_client++){
            ssl_client_fd[idx_client] = NULL;
        }
        idx_client = 0;
    #endif

    char response_code[32];

    stcp_http_webserver_bzero(_stcpWI, _stcpWH);
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

        if (stcp_webserver_setup_data.stcp_keepalive_sec > 0 || stcp_webserver_setup_data.stcp_keepalive_millisec > 0){
            tv_timer.tv_sec = stcp_webserver_setup_data.stcp_keepalive_sec;
            tv_timer.tv_usec = stcp_webserver_setup_data.stcp_keepalive_millisec * 1000;
            activity = select(max_sd + 1 , &readfds , NULL , NULL , &tv_timer);
        }
        else {
            activity = select(max_sd + 1 , &readfds , NULL , NULL , NULL);
        }
        if ((activity < 0) && (errno!=EINTR))   
        {
            stcp_debug(__func__, STCP_DEBUG_ERROR, "select error\n");
        }

        if (FD_ISSET(init_data.socket_f, &readfds) && stcp_server_state == STCP_SERVER_RUNING)   
        {   
            tv_timer.tv_sec = stcp_setup_data.stcp_timeout_sec;
            tv_timer.tv_usec = stcp_setup_data.stcp_timeout_millisec * 1000;
            if ((init_data.connection_f = accept(init_data.socket_f, (SA*)&cli, &len))<0){  
                stcp_debug(__func__, STCP_DEBUG_INFO, "accept failed\n");
            }
            else {
                for (idx_client = 0; idx_client < MAX_CLIENT; idx_client++){
                    if(client_fd[idx_client] == 0 ){
                        stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "new connection (%d:%d) %s:%d\n" ,
                         init_data.connection_f, idx_client, inet_ntoa(cli.sin_addr), ntohs(cli.sin_port)
                        );
                        if (tv_timer.tv_sec > 0 || tv_timer.tv_usec > 0){
                            stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "connection timeout: %u seconds %u ms\n",
                             stcp_setup_data.stcp_timeout_sec,
                             stcp_setup_data.stcp_timeout_millisec
                            );
                            setsockopt(init_data.connection_f, SOL_SOCKET, SO_RCVTIMEO, (const void *) &tv_timer, sizeof tv_timer);
                        }
                        client_fd[idx_client] = init_data.connection_f;
                        client_addr[idx_client] = cli.sin_addr;
                        #ifdef __STCP_SSL__
                            if (_stcpWI->comm_protocol){
                                init_data.ssl_connection_f = NULL;
                                init_data.ssl_connection_f = SSL_new(ssl_ctx);
                                if (init_data.ssl_connection_f == NULL){
                                    stcp_debug(__func__, STCP_DEBUG_WARNING, "ssl creation failed\n");
                                    goto close_client;
                                }
                                SSL_set_fd(init_data.ssl_connection_f, init_data.connection_f);
                                if (SSL_accept(init_data.ssl_connection_f) == -1){
                                    stcp_debug(__func__, STCP_DEBUG_WARNING, "ssl accept failed\n");
                                    init_data.ssl_connection_f = NULL;
                                    goto close_client;
                                }
                                #if !defined __XTENSA__ && !defined ESP_PLATFORM
                                X509 *cert = NULL;
                                cert = SSL_get_peer_certificate(init_data.ssl_connection_f);
                                if (cert != NULL){
                                    char *sslInfoBuff = NULL;
                                    sslInfoBuff = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                                    if (sslInfoBuff != NULL){
                                        stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "Subject: %s\n", sslInfoBuff);
                                        free(sslInfoBuff);
                                        sslInfoBuff = NULL;
                                    }
                                    sslInfoBuff = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                                    if (sslInfoBuff != NULL){
                                        stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "Issuer: %s\n", sslInfoBuff);
                                        free(sslInfoBuff);
                                        sslInfoBuff = NULL;
                                    }
                                    free(cert);
                                    cert = NULL;
                                }
                                else {
                                    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "no certificate\n");
                                }
                                #endif
                                ssl_client_fd[idx_client] = init_data.ssl_connection_f;
                            }
                        #endif
                        break;   
                    }   
                }
            }
        }
        else if (stcp_server_state == STCP_SERVER_RUNING &&
         (stcp_webserver_setup_data.stcp_keepalive_sec > 0 || stcp_webserver_setup_data.stcp_keepalive_millisec > 0)
        ){
            for (idx_client = 0; idx_client<MAX_CLIENT; idx_client++){
                if (keep_alive_cnt[idx_client] > 0 && client_fd[idx_client] > 0){
                    gettimeofday(&tv_timer, NULL);
                    if ((keep_alive_cnt[idx_client] +
                      (stcp_webserver_setup_data.stcp_keepalive_sec*1000) +
                      stcp_webserver_setup_data.stcp_keepalive_millisec
                     ) <=
                     ((tv_timer.tv_sec%60)*1000 + (tv_timer.tv_usec/1000))
                    ){
                        keep_alive_cnt[idx_client] = 0;
                        if (_stcpWI->comm_protocol){
                            #ifdef __STCP_SSL__
                                if (init_data.ssl_connection_f != NULL){
                                    SSL_shutdown(init_data.ssl_connection_f);
                                    SSL_free(init_data.ssl_connection_f);
                                    init_data.ssl_connection_f = NULL;
                                }
                                ssl_client_fd[idx_client] = init_data.ssl_connection_f;
                            #endif
                        }
                        close(client_fd[idx_client]);
                        client_fd[idx_client] = 0;
                        memset(&client_addr[idx_client], 0x00, sizeof(struct in_addr));
                        stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "one client connection\033[1;31m closed\033[0m (keep alive timeout) (%i)\n", idx_client);
                    }
                }
            }
        }
        elapsed_connection_counter = time(NULL);
        for (idx_client = 0; idx_client < MAX_CLIENT && stcp_server_state == STCP_SERVER_RUNING; idx_client++){
            init_data.connection_f = client_fd[idx_client];
            #ifdef __STCP_SSL__
                if (_stcpWI->comm_protocol){
                    init_data.ssl_connection_f = ssl_client_fd[idx_client];
                }
            #endif

            if (FD_ISSET(init_data.connection_f , &readfds))   
            {
                stcp_bytes = 0;
                stcp_size = 8;
                idx_chr = 0;
                proc_state = STCP_PROCESS_GET_HEADER;
                for(idx_shat = 0; idx_shat < sizeof(slow_http_attack_handler.shat_counter_record); idx_shat++){
                    if (slow_http_attack_handler.shat_counter_record[idx_shat] >= stcp_webserver_setup_data.stcp_slow_http_attack_counter_accepted){
                        if (!memcmp(&(slow_http_attack_handler.shat_addr_record[idx_shat]), &client_addr[idx_client], sizeof(struct in_addr))){
                            if (time(NULL) - slow_http_attack_handler.shat_time_record[idx_shat] < stcp_webserver_setup_data.stcp_slow_http_attack_blocking_time){
                                idx_shat = 99;
                                break;
                            }
                            else {
                                memset(&(slow_http_attack_handler.shat_addr_record[idx_shat]), 0x00, sizeof(struct in_addr));
                                slow_http_attack_handler.shat_counter_record[idx_shat] = 0;
                                slow_http_attack_handler.shat_time_record[idx_shat] = 0;
                            }
                        }
                        else if (slow_http_attack_handler.shat_counter_record[idx_shat]){
                            if (time(NULL) - slow_http_attack_handler.shat_time_record[idx_shat] >= stcp_webserver_setup_data.stcp_slow_http_attack_blocking_time){
                                memset(&(slow_http_attack_handler.shat_addr_record[idx_shat]), 0x00, sizeof(struct in_addr));
                                slow_http_attack_handler.shat_counter_record[idx_shat] = 0;
                                slow_http_attack_handler.shat_time_record[idx_shat] = 0;
                            }
                        }
                    }
                }
                stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "\033[1;31m processing\033[0m connection (%d:%d)\n",
                 init_data.connection_f,
                 idx_client
                );
                while(stcp_server_state == STCP_SERVER_RUNING && idx_shat != 99){
                    if ((time(NULL) - elapsed_connection_counter) > stcp_webserver_setup_data.stcp_max_elapsed_connection){
                        break;
                    }
                    if (proc_state == STCP_PROCESS_GET_HEADER){
                        slow_http_attack_handler.shat_timer = time(NULL);
                        if (!_stcpWI->comm_protocol){
                            stcp_bytes = stcp_recv_data(init_data, buffer, buffer_size);
                        }
                        else {
                            #ifdef __STCP_SSL__
                                stcp_bytes = stcp_ssl_recv_data(init_data, buffer, buffer_size);
                            #else
                                goto close_client;
                            #endif
                        }
                        if ((time(NULL) - slow_http_attack_handler.shat_timer) > 0 && stcp_bytes < 2048 && (stcp_bytes > 0 || idx_chr > 0)){
                            slow_http_attack_handler.shat_counter++;
                            stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "slow HTTP Attack Triggered from %s\n",
                             inet_ntoa(client_addr[idx_client])
                            );
                        }
                        else {
                            slow_http_attack_handler.shat_counter = 0;
                        }
                        if (slow_http_attack_handler.shat_counter >= stcp_webserver_setup_data.stcp_slow_http_attack_counter_accepted){
                            stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "blocking slow HTTP Attack from %s\n",
                             inet_ntoa(client_addr[idx_client])
                            );
                            for(idx_shat = 0; idx_shat < sizeof(slow_http_attack_handler.shat_counter_record); idx_shat++){
                                if (slow_http_attack_handler.shat_counter_record[idx_shat] == 0){
                                    memcpy(&(slow_http_attack_handler.shat_addr_record[idx_shat]), &client_addr[idx_client], sizeof(struct in_addr));
                                    slow_http_attack_handler.shat_counter_record[idx_shat]++;
                                    slow_http_attack_handler.shat_time_record[idx_shat] = time(NULL);
                                }
                                else {
                                    slow_http_attack_handler.shat_counter_record[idx_shat]++;
                                }
                            }
                            break;
                        }
                        if (stcp_bytes <= 0){
                            if(strstr((char *) _stcpWI->rcv_header, "HTTP") != NULL || stcp_bytes < 0){
                                stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "Lost Connection.. received data:\n%s\n", _stcpWI->rcv_header);
                                if (slow_http_attack_handler.shat_counter + 1 >= stcp_webserver_setup_data.stcp_slow_http_attack_counter_accepted){
                                    slow_http_attack_handler.shat_counter++;
                                    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "blocking slow HTTP Attack from %s\n",
                                     inet_ntoa(client_addr[idx_client])
                                    );
                                    for(idx_shat = 0; idx_shat < sizeof(slow_http_attack_handler.shat_counter_record); idx_shat++){
                                        if (slow_http_attack_handler.shat_counter_record[idx_shat] == 0){
                                            memcpy(&(slow_http_attack_handler.shat_addr_record[idx_shat]), &client_addr[idx_client], sizeof(struct in_addr));
                                            slow_http_attack_handler.shat_counter_record[idx_shat]++;
                                            slow_http_attack_handler.shat_time_record[idx_shat] = time(NULL);
                                        }
                                        else {
                                            slow_http_attack_handler.shat_counter_record[idx_shat]++;
                                        }
                                    }
                                    break;
                                }
                                goto close_client;
                            }
                            else if (keep_alive_cnt[idx_client] > 0){
                                gettimeofday(&tv_timer, NULL);
                                if ((keep_alive_cnt[idx_client] +
                                  (stcp_webserver_setup_data.stcp_keepalive_sec*1000) +
                                  stcp_webserver_setup_data.stcp_keepalive_millisec
                                 ) <=
                                 ((tv_timer.tv_sec%60)*1000 + (tv_timer.tv_usec/1000))
                                ){
                                    keep_alive_cnt[idx_client] = 0;
                                    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "received 0 and keep alive timeout\n");
                                    goto close_client;
                                }
                            }
                            else if (stcp_bytes || idx_chr){
                                goto stcp_func;
                            }
                            stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "received 0 and keep alive not active\n");
                            goto close_client;
                        }
                        else {
                            while (stcp_size < (idx_chr + stcp_bytes) + 2){
                                stcp_size = stcp_size + 8;
                                if (stcp_size >= (idx_chr + stcp_bytes) + 2){
                                    _stcpWI->rcv_header = (unsigned char *) realloc(_stcpWI->rcv_header, (stcp_size + 1)*sizeof(unsigned char));
                                }
                            }
                            buffer[stcp_bytes] = 0x00;
                            memcpy(_stcpWI->rcv_header + idx_chr, buffer, stcp_bytes);
                            _stcpWI->rcv_header[idx_chr + stcp_bytes] = 0x00;
                            if(strstr((char *) _stcpWI->rcv_header, "HTTP") == NULL){
                                if(_stcpWI->rcv_header[idx_chr + stcp_bytes - 1] == '\n'){
                                    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "goto stcp origin function\n");
                                    goto stcp_func;
                                }
                                idx_chr += stcp_bytes - 1;
                                if (idx_chr > stcp_webserver_setup_data.stcp_max_received_data){
                                    goto stcp_func;
                                }
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
                                            _stcpWI->rcv_content = (unsigned char *) realloc(_stcpWI->rcv_content, stcp_size*sizeof(unsigned char));
                                            memset(_stcpWI->rcv_content, 0x00, stcp_size);
                                            memcpy(_stcpWI->rcv_content, _stcpWI->rcv_header + idx_chr, (stcp_bytes - 4));
                                            _stcpWI->rcv_header[idx_chr] = 0x00;
                                            _stcpWI->rcv_header = (unsigned char *) realloc(_stcpWI->rcv_header, (idx_chr + 1)*sizeof(unsigned char));
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
                                if (idx_chr > stcp_webserver_setup_data.stcp_max_received_header){
                                    break;
                                }
                            }
                            if ((_stcpWI->content_length == 0 || (idx_chr + 1) >= _stcpWI->content_length) &&
                             proc_state == STCP_PROCESS_GET_CONTENT
                            ){
                                break;
                            }
                        }

                    }
                    else{
                        slow_http_attack_handler.shat_timer = time(NULL);
                        if (!_stcpWI->comm_protocol){
                            stcp_bytes = stcp_recv_data(init_data, buffer, buffer_size);
                        }
                        else {
                            #ifdef __STCP_SSL__
                                stcp_bytes = stcp_ssl_recv_data(init_data, buffer, buffer_size);
                            #else
                                goto close_client;
                            #endif
                        }
                        if ((time(NULL) - slow_http_attack_handler.shat_timer) > 0 && stcp_bytes < 2048){
                            slow_http_attack_handler.shat_counter++;
                        }
                        else {
                            slow_http_attack_handler.shat_counter = 0;
                        }
                        if (slow_http_attack_handler.shat_counter >= stcp_webserver_setup_data.stcp_slow_http_attack_counter_accepted){
                            for(idx_shat = 0; idx_shat < sizeof(slow_http_attack_handler.shat_counter_record); idx_shat++){
                                if (slow_http_attack_handler.shat_counter_record[idx_shat] == 0){
                                    memcpy(&(slow_http_attack_handler.shat_addr_record[idx_shat]), &client_addr[idx_client], sizeof(struct in_addr));
                                    slow_http_attack_handler.shat_counter_record[idx_shat]++;
                                    slow_http_attack_handler.shat_time_record[idx_shat] = time(NULL);
                                }
                                else {
                                    slow_http_attack_handler.shat_counter_record[idx_shat]++;
                                }
                            }
                            break;
                        }
                        if (stcp_bytes <= 0){
                            stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "Lost Connection..\n");
                            goto close_client;
                        }
                        else {
                            while (stcp_size < (idx_chr + stcp_bytes) + 2){
                                stcp_size = stcp_size + 8;
                                if (stcp_size >= idx_chr + 2){
                                    _stcpWI->rcv_content = (unsigned char *) realloc(_stcpWI->rcv_content, stcp_size*sizeof(unsigned char));
                                }
                            }
                            memcpy(_stcpWI->rcv_content + idx_chr, buffer, stcp_bytes);
                            idx_chr = idx_chr + stcp_bytes;
                            _stcpWI->rcv_content[idx_chr] = 0x00;

                            if (idx_chr > stcp_webserver_setup_data.stcp_max_received_data){
                                break;
                            }
                        }
                        if (_stcpWI->content_length > 0 && (idx_chr) >= _stcpWI->content_length){
                            break;
                        }
                    }
                }
                if (idx_chr > 0){
                    stcp_debug(__func__, STCP_DEBUG_INFO, "Content Received %li bytes\n", (long) idx_chr);
                }

                memset(response_code, 0x00, sizeof(response_code));
                response_content = stcp_http_webserver_select_response(_stcpWI, _stcpWList, response_code);
                strcpy(_stcpWI->ipaddr, inet_ntoa(client_addr[idx_client]));
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
                     64,
                     "%s{\"status\":\"error\",\"code\":204,\"message\":\"unknown target/request\"}\r\n\r\n",
                     _stcpWI->server_header
                    );
                    if (buffer_info == NULL){
                        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to generate webserver content\n");
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
                else if (memcmp(response_content, "open_file:", 10) == 0){
                    char content_file_name[strlen((char *) response_content) - 9];
                    memset(content_file_name, 0x00, sizeof(content_file_name));
                    memcpy(content_file_name, response_content + 10, (strlen((char *) response_content) - 10));
                    if (stcp_http_webserver_send_file(init_data, _stcpWI, _stcpWH, response_code, content_file_name) == -1){
                        goto close_client;
                    }
                    goto stcp_connection_check;
                }
                else if (memcmp(response_content, "callback:", 9) == 0){
                    memcpy(&_func_tmp, response_content + 9, sizeof(void *));
                    int8_t retval = stcp_http_webserver_callback(
                     init_data,
                     (const void * (*)(stcpSock, stcpWInfo *, stcpWHead *, stcpWList, int8_t *)) _func_tmp,
                     _stcpWI,
                     _stcpWH,
                     _stcpWList
                    );
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
                     strlen((char *) response_content)) != 0
                    ){
                        goto close_client;
                    }
                    buffer_info = stcp_http_content_generator(
                     64,
                     "%s%s", _stcpWI->server_header, response_content
                    );
                    if (buffer_info == NULL){
                        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to generate webserver content\n");
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
                    if (strstr(_stcpWI->server_header, "keep-alive") != NULL &&
                     (stcp_webserver_setup_data.stcp_keepalive_sec > 0 ||
                     stcp_webserver_setup_data.stcp_keepalive_millisec > 0)
                    ){
                        gettimeofday(&tv_timer, NULL);
                        keep_alive_cnt[idx_client] = (uint16_t) ((tv_timer.tv_sec%60)*1000 + (tv_timer.tv_usec/1000));
                        goto stcp_next;
                    }

                goto close_client;
                
                stcp_func:
                    response_content = stcp_http_webserver_select_tcp_response(_stcpWI->rcv_header, _stcpWList);
                    if(response_content != NULL){
                        memcpy(&_func_tmp, response_content + 9, sizeof(void *));
                        int8_t retval = stcp_http_webserver_callback(
                         init_data,
                         (const void * (*)(stcpSock, stcpWInfo *, stcpWHead *, stcpWList, int8_t *)) _func_tmp,
                         _stcpWI,
                         _stcpWH,
                         _stcpWList
                        );
                        if (retval == -1 || retval == 1){
                            goto close_client;
                        }
                        goto stcp_next;
                    }

                /* user handling end here */
                close_client:
                    if (_stcpWI->comm_protocol){
                        #ifdef __STCP_SSL__
                            if (init_data.ssl_connection_f != NULL){
                                if (!SSL_get_shutdown(init_data.ssl_connection_f)){
                                    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "shutdown SSL\n");
                                    SSL_shutdown(init_data.ssl_connection_f);
                                }
                                else {
                                    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "release without shutdown the SSL\n");
                                }
                                SSL_free(init_data.ssl_connection_f);
                                init_data.ssl_connection_f = NULL;
                            }
                            ssl_client_fd[idx_client] = init_data.ssl_connection_f;
                        #endif
                    }
                    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "one client connection \033[1;31m closed\033[0m (%d:%d)\n", init_data.connection_f, idx_client);
                    close(init_data.connection_f);
                    init_data.connection_f = 0;
                    keep_alive_cnt[idx_client] = 0;
                stcp_next:
                    stcp_http_webserver_bzero(_stcpWI, _stcpWH);
                    client_fd[idx_client] = init_data.connection_f;
            }
        }
    }
    if (!_stcpWI->comm_protocol){
        stcp_close(&init_data);
    }
    else {
        #ifdef __STCP_SSL__
            SSL_CTX_free(ssl_ctx);
            ssl_ctx = NULL;
            stcp_ssl_close(&init_data);
        #endif
    }
    stcp_http_webserver_free(_stcpWI, _stcpWH, &_stcpWList);
    free(buffer);
    buffer = NULL;
    stcp_server_state = STCP_SERVER_STOPED;
    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "server terminated!\n");
    return 0x00;
}

/**
 * Send stop signal to STCP Webserver (this function will be terminated after stcp_server_state changed to STCP_SERVER_STOPED)
 */
void stcp_http_webserver_stop(){
    if (stcp_server_state != STCP_SERVER_RUNING){
        return;
    }
    stcp_server_state = STCP_SERVER_STOP;
    stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "please wait...\n");
    while(stcp_server_state == STCP_SERVER_STOP){
        usleep(10000);
    }
}
#endif

#ifndef __STCP_DONT_USE_CLIENT__
/**
 * Initialize TCP/IP client connection until accepted by server
 * @param[in] ADDRESS a constant character pointer that inform the host address
 * @param[in] PORT an unsigned short that inform server port
 * @return stcpSock (__socket_f__ (member of stcpSock) > 0 if success)
 */
stcpSock stcp_client_init(
 const char *ADDRESS,
 uint16_t PORT
){
    stcpSock init_data;
    init_data.socket_f = 0;
    init_data.connection_f = 0;
    int8_t retval = 0;
    struct sockaddr_in servaddr;

    do{
        init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
        if (init_data.socket_f < 0) {
            stcp_debug(__func__, STCP_DEBUG_CRITICAL, "socket creation failed...\n");
            retval = (int8_t) -1;
        }
        else{
            retval = (int8_t) 0;
            stcp_debug(__func__, STCP_DEBUG_INFO, "Socket successfully created : %d\n", init_data.socket_f);
            memset(&servaddr, 0x00, sizeof(servaddr));
            servaddr.sin_family = AF_INET;
            servaddr.sin_port = (in_port_t) htons(PORT);
            if(stcp_check_ip(ADDRESS) != 0){
                struct hostent *host = NULL;
                host = gethostbyname(ADDRESS);
                if (host != NULL){
                    servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
                }
                else {
                    stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to get host by name\n", ADDRESS);
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

            stcp_debug(__func__, STCP_DEBUG_INFO, "waiting for server...\n");
            if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
                struct timeval tv;
                tv.tv_sec = (time_t) stcp_setup_data.stcp_timeout_sec;
                tv.tv_usec = (suseconds_t) (stcp_setup_data.stcp_timeout_millisec * 1000);
                retval = stcp_connect_with_timeout(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr), &tv);
                if (retval != 0){
                    stcp_debug(__func__, STCP_DEBUG_WARNING, "waiting for server timeout\n");
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
	        stcp_debug(__func__, STCP_DEBUG_INFO, "connected to the server..\n");
        }
    } while (retval < 0 && stcp_setup_data.stcp_retry_mode == (int8_t) INFINITE_RETRY);
    return init_data;
}

#ifdef __STCP_SSL__
/**
 * Initialize SSL/TLS client connection until accepted by server
 * @param[in] ADDRESS a constant character pointer that inform the host address
 * @param[in] PORT an unsigned short that inform server port
 * @return stcpSock (__socket_f__ (member of stcpSock) > 0 if success)
 */
stcpSock stcp_ssl_client_init(
 const char *ADDRESS,
 uint16_t PORT
){
    stcpSock init_data;
    init_data.socket_f = 0;
    init_data.connection_f = 0;
    init_data.ssl_connection_f = NULL;
    int8_t retval = 0;
    struct sockaddr_in servaddr;

    do{
        init_data.socket_f = socket(AF_INET, SOCK_STREAM, 0); 
        if (init_data.socket_f < 0) {
            stcp_debug(__func__, STCP_DEBUG_CRITICAL, "socket creation failed...\n");
            retval = (int8_t) -1;
        }
        else{
            retval = (int8_t) 0;
            stcp_debug(__func__, STCP_DEBUG_INFO, "Socket successfully created : %d\n", init_data.socket_f);
            memset(&servaddr, 0x00, sizeof(servaddr));
            servaddr.sin_family = AF_INET;
            servaddr.sin_port = (in_port_t) htons(PORT);
            if(stcp_check_ip(ADDRESS) != 0){
                struct hostent *host = NULL;
                host = gethostbyname(ADDRESS);
                if (host != NULL){
                    servaddr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*) host->h_addr_list[0])));
                }
                else {
                    stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to get host by name\n", ADDRESS);
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

            stcp_debug(__func__, STCP_DEBUG_INFO, "waiting for server...\n");
            if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
                struct timeval tv;
                tv.tv_sec = stcp_setup_data.stcp_timeout_sec;
                tv.tv_usec = stcp_setup_data.stcp_timeout_millisec * 1000;
                retval = stcp_connect_with_timeout(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr), &tv);
                if (retval != 0){
                    stcp_debug(__func__, STCP_DEBUG_WARNING, "waiting for server timeout\n");
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
            #ifdef SSLv23_client_method
                ssl_ctx = SSL_CTX_new (SSLv23_client_method ());
            #else
                ssl_ctx = SSL_CTX_new (TLSv1_2_client_method ());
            #endif

            if (ssl_ctx == NULL){
                stcp_debug(__func__, STCP_DEBUG_WARNING, "unable to create new SSL context structure\n");
            }

            #if !defined __XTENSA__ && !defined ESP_PLATFORM
            unsigned char* sslCertKey = NULL;
            stcp_ssl_certkey_type certkeyType = STCP_SSL_CERT_TYPE_FILE;
            shilink_print(stcp_certkey_collection);
            sslCertKey = stcp_ssl_get_cert(ADDRESS, &certkeyType);
            int8_t cert_flag = 0;
            if (sslCertKey != NULL){
                if (certkeyType == STCP_SSL_CERT_TYPE_FILE){
                    if (SSL_CTX_use_certificate_file(ssl_ctx, (const char *) sslCertKey, SSL_FILETYPE_PEM) <= 0)
                    {
                        stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to open certificate file\n");
                    }
                }
                else {
                    if (SSL_CTX_use_certificate_ASN1(ssl_ctx, strlen((const char *) sslCertKey), sslCertKey) <= 0)
                    {
                        stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to add certificate\n");
                    }
                }
                stcp_debug(__func__, STCP_DEBUG_INFO, "succes to use certificate\n");
                cert_flag = 1;
            }
            sslCertKey = NULL;
            sslCertKey = stcp_ssl_get_key(ADDRESS, &certkeyType);
            if (sslCertKey != NULL){
                if (certkeyType == STCP_SSL_KEY_TYPE_FILE){
                    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, (const char *) sslCertKey, SSL_FILETYPE_PEM) <= 0)
                    {
                        stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to open private key file\n");
                    }
                }
                else {
                    if (SSL_CTX_use_PrivateKey_ASN1(0, ssl_ctx, sslCertKey, strlen((const char *) sslCertKey)) <= 0)
                    {
                        stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to add privat key\n");
                    }
                }
                if (!SSL_CTX_check_private_key(ssl_ctx))
                {
                    stcp_debug(__func__, STCP_DEBUG_WARNING, "Private key does not match the public certificate\n");
                }
                stcp_debug(__func__, STCP_DEBUG_INFO, "succes to use private key\n");
                cert_flag = 1;
            }
            #endif
            init_data.ssl_connection_f = SSL_new(ssl_ctx);
            SSL_set_fd(init_data.ssl_connection_f, init_data.socket_f);

            int err = SSL_connect(init_data.ssl_connection_f);
            if (err != 1){
                stcp_debug(__func__, STCP_DEBUG_WARNING, "ssl connection failed\n");
            }
            #if !defined __XTENSA__ && !defined ESP_PLATFORM
            if (cert_flag != 0){
                X509 *cert = NULL;
                cert = SSL_get_peer_certificate(init_data.ssl_connection_f);
                if (cert != NULL){
                    char *sslInfoBuff = NULL;
                    sslInfoBuff = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                    if (sslInfoBuff != NULL){
                        stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "Subject: %s\n", sslInfoBuff);
                        free(sslInfoBuff);
                        sslInfoBuff = NULL;
                    }
                    sslInfoBuff = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                    if (sslInfoBuff != NULL){
                        stcp_debug(__func__, STCP_DEBUG_WEBSERVER, "Issuer: %s\n", sslInfoBuff);
                        free(sslInfoBuff);
                        sslInfoBuff = NULL;
                    }
                    free(cert);
                    cert = NULL;
                }
            }
            #endif
            init_data.connection_f = init_data.socket_f;
	        stcp_debug(__func__, STCP_DEBUG_INFO, "connected to the server..\n");
            SSL_CTX_free(ssl_ctx);
        }
    } while (retval < 0 && stcp_setup_data.stcp_retry_mode == (int8_t) INFINITE_RETRY);
    return init_data;
}
#endif

/**
 * get size of input file
 * @param[in] _file_name a constant character pointer that inform the file path
 * @return >= 0 if success, -1 if failed to open file
 */
long stcp_get_file_size(const char *_file_name){
    #ifdef __STCP_DEBUG__
    stcp_debug(__func__, STCP_DEBUG_INFO, "file name: %s\n", _file_name);
    #endif

    FILE *stcp_file = NULL;
    uint8_t try_times = 3;

    do{
    	stcp_file = fopen(_file_name, "r");
        try_times--;
    } while (stcp_file == NULL && try_times > 0);

    if (stcp_file == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to open \"%s\"\n", _file_name);
        #endif
        return -1;
    }

    long content_size = 0;
    fseek(stcp_file, 0L, SEEK_END);
    content_size = ftell(stcp_file);

    #ifdef __STCP_DEBUG__
    stcp_debug(__func__, STCP_DEBUG_INFO, "file size: %li\n", content_size);
    #endif

    fclose(stcp_file);
    stcp_file = NULL;
    return content_size;
}

/**
 * Send file over TCP/IP or SSL/TLS
 * @param[in] _init_data socket information that stored as stcpSock structure
 * @param[in] _file_name a constant character pointer that inform the file path
 * @param[in] _socket_type TCP/IP or SSL (if you want to send file over TCP/IP set this field to 10, but if you want to send file over SSL/TLS set this field to another value)
 * @return 0 if success, 1 if failed to open file, or 2 if failed to allocate buffer memmory (8 bytes integer value)
 */
static int8_t stcp_socket_send_file(
 stcpSock _init_data,
 const char *_file_name,
 int8_t _socket_type
){
    #ifdef __STCP_DEBUG__
    stcp_debug(__func__, STCP_DEBUG_INFO, "file name: %s\n", _file_name);
    #endif

    FILE *stcp_file = NULL;
    uint8_t try_times = 0x03;

    do{
    	stcp_file = fopen(_file_name, "rb");
        try_times--;
    } while (stcp_file == NULL && try_times > 0);

    if (stcp_file == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to open \"%s\"\n", _file_name);
        #endif
        return 0x01;
    }

    long content_size = 0;
    fseek(stcp_file, 0L, SEEK_END);
    content_size = ftell(stcp_file);

    fseek(stcp_file, 0L, SEEK_SET);

    unsigned char *file_content = NULL;
    file_content = (unsigned char *) malloc(stcp_setup_data.stcp_size_per_send * sizeof(unsigned char));
    if (file_content == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate memory for file_content\n");
        #endif
        fclose(stcp_file);
        stcp_file = NULL;
        return 0x02;
    }

    uint32_t size_recv = 0;
    size_t bytes = 0;
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
                    stcp_debug(__func__, STCP_DEBUG_WARNING, "please enable __STCP_SSL__ on shiki-tcp-ip-tools.h\n");
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
                        stcp_debug(__func__, STCP_DEBUG_WARNING, "please enable __STCP_SSL__ on shiki-tcp-ip-tools.h\n");
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
    return 0x00;
}

/**
 * Send file over TCP/IP
 * @param[in] _init_data socket information that stored as stcpSock structure
 * @param[in] _file_name a constant character pointer that inform the file path
 * @return 0 if success, 1 if failed to open file, or 2 if failed to allocate buffer memmory (8 bytes integer value)
 */
int8_t stcp_send_file(stcpSock _init_data, const char *_file_name){
    return stcp_socket_send_file(_init_data, _file_name, STCP_TCP);
}

#ifdef __STCP_SSL__
/**
 * Send file over SSL/TLS
 * @param[in] _init_data socket information that stored as stcpSock structure
 * @param[in] _file_name a constant character pointer that inform the file path
 * @return 0 if success, 1 if failed to open file, or 2 if failed to allocate buffer memmory (8 bytes integer value)
 */
int8_t stcp_ssl_send_file(stcpSock _init_data, const char *_file_name){
    return stcp_socket_send_file(_init_data, _file_name, STCP_SSL);
}
#endif
#endif

/**
 * Send buffer data over TCP/IP
 * @param[in] _init_data socket information that stored as stcpSock structure
 * @param[in] buff a constant unsigned character pointer of data that will be send
 * @param[in] size_set a long integer (32 bit) parameter of data size that will be send
 * @return size of data that has been send, -1 if failed to send data (32 bit integer value)
 */
int32_t stcp_send_data(stcpSock _init_data, const unsigned char* buff, int32_t size_set){
    int32_t bytes;
    int32_t bytes_aviable = 0;
    uint16_t timeout_cstart = 0;
    uint16_t timeout_cvalue = 0;
    /* check Socket Output Buffer before send any data */
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
                stcp_debug(__func__, STCP_DEBUG_WARNING, "send 0 data. request timeout (0)\n");
                return -1;
            }
        }
    } while (bytes_aviable > 0);
    /* send data */
    bytes = (int32_t) write(_init_data.connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, STCP_DEBUG_INFO, "success to send %d data\n", bytes);
    else if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
        stcp_debug(__func__, STCP_DEBUG_WARNING, "send %d data. request timeout (1)\n", bytes);
    }
    else {
        stcp_debug(__func__, STCP_DEBUG_WARNING, "request timeout\n");
    }
    return bytes;
}

/**
 * Receive buffer data over TCP/IP
 * @param[in] _init_data socket information that stored as stcpSock structure
 * @param[out] buff an unsigned character pointer of stored variable
 * @param[in] size_set a long integer (32 bit) parameter of data size that will be send
 * @return size of data that has been received, -1 if failed to receive data (32 bit integer value)
 */
int32_t stcp_recv_data(stcpSock _init_data, unsigned char* buff, int32_t size_set){
    int32_t bytes;
    bytes = (int32_t) read(_init_data.connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, STCP_DEBUG_INFO, "success to receive %li data\n", (long) bytes);
    else if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
        stcp_debug(__func__, STCP_DEBUG_WARNING, "receive %li data. request timeout or finished\n", (long) bytes);
    }
    else {
        stcp_debug(__func__, STCP_DEBUG_WARNING, "request timeout\n");
    }
    return bytes;
}

#ifdef __STCP_SSL__
/**
 * Send buffer data over SSL/TLS
 * @param[in] _init_data socket information that stored as stcpSock structure
 * @param[in] buff a constant unsigned character pointer of data that will be send
 * @param[in] size_set a long integer (32 bit) parameter of data size that will be send
 * @return size of data that has been send, -1 if failed to send data (32 bit integer value)
 */
int32_t stcp_ssl_send_data(stcpSock _init_data, const unsigned char* buff, int32_t size_set){
    int32_t bytes;
    int32_t bytes_aviable = 0;
    uint16_t timeout_cstart = 0;
    uint16_t timeout_cvalue = 0;
    struct timeval tv;
    /* check Socket Output Buffer before send any data */
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
                stcp_debug(__func__, STCP_DEBUG_WARNING, "send 0 data. request timeout\n");
                return -1;
            }
        }
    } while (bytes_aviable > 0);
    /* send data */
    bytes = (int32_t) SSL_write(_init_data.ssl_connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, STCP_DEBUG_INFO, "success to send %d data\n", bytes);
    else if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
        stcp_debug(__func__, STCP_DEBUG_WARNING, "send %d data. request timeout\n", bytes);
    }
    else {
        stcp_debug(__func__, STCP_DEBUG_WARNING, "request timeout\n");
    }
    return bytes;
}

/**
 * Receive buffer data over SSL/TLS
 * @param[in] _init_data socket information that stored as stcpSock structure
 * @param[out] buff an unsigned character pointer of stored variable
 * @param[in] size_set a long integer (32 bit) parameter of data size that will be send
 * @return size of data that has been received, -1 if failed to receive data (32 bit integer value)
 */
int32_t stcp_ssl_recv_data(stcpSock _init_data, unsigned char* buff, int32_t size_set){
    int32_t bytes;
    bytes = (int32_t) SSL_read(_init_data.ssl_connection_f, buff, size_set*sizeof(char));
    if (bytes >= 0) stcp_debug(__func__, STCP_DEBUG_INFO, "success to receive %d data\n", bytes);
    else if (stcp_setup_data.stcp_timeout_sec > 0 || stcp_setup_data.stcp_timeout_millisec > 0){
        stcp_debug(__func__, STCP_DEBUG_WARNING, "receive %d data. request timeout or finished\n", bytes);
    }
    else {
        stcp_debug(__func__, STCP_DEBUG_WARNING, "request timeout\n");
    }
    return bytes;
}
#endif

#ifndef __STCP_DONT_USE_CLIENT__
/**
 * Parsing url input to get some information like protocol (http/https), host, port, and endpoint
 * @param[in] _url a constant character pointer of url information
 * @param[out] _protocol an integer (8 bits) pointer of protocol type (http/https)
 * @param[out] _host a stcpSHead pointer structur that will be store the informations of host position and size in url input
 * @param[out] _end_point a stcpSHead pointer structur that will be store the informations of endpoint position and size in url input
 * @param[out] _port an unsigned short pointer of port
 * @return 0 if success, 1 if failed to allocate buffer memmory, 2 if failed to determine protocol
 */
int8_t stcp_url_parser(const char *_url, int8_t *_protocol, stcpSHead *_host, stcpSHead *_end_point, uint16_t *_port){
    if (strncmp(_url, "http://", 7) == 0 || strncmp(_url, "https://", 8) == 0){
        stcpSHead sub_tmp;
        char *buff = NULL;
        buff = (char *) malloc(9*sizeof(char));
        if (buff == NULL){
            #ifdef __STCP_DEBUG__
            stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate buff valriable memory\n");
            #endif
            return 0x01;
        }
        uint16_t idx_char_url = 0;
        uint16_t idx_char_buff = 0;
        memset(buff, 0x00, 9*sizeof(char));
        if (strncmp(_url, "http://", 7) == 0){
            *_protocol = 0x00;
            *_port = 80;
            idx_char_url = 7;
        }
        else {
            *_protocol = 0x01;
            *_port = 443;
            idx_char_url = 8;
        }
        sub_tmp.stcp_sub_pos = idx_char_url;
        sub_tmp.stcp_sub_size = 0;
        while(_url[idx_char_url] != '/' && _url[idx_char_url] != ':' && _url[idx_char_url] != 0x00){
            idx_char_url++;
            sub_tmp.stcp_sub_size++;
        }
        *_host = sub_tmp;
        sub_tmp.stcp_sub_pos = 6;
        sub_tmp.stcp_sub_size = 1;
        *_end_point = sub_tmp;
        if (_url[idx_char_url] == 0x00){
            free(buff);
            buff = NULL;
            return 0x00;
        }
        if (_url[idx_char_url] == ':'){
            idx_char_url++;
            while(_url[idx_char_url] != '/' && _url[idx_char_url] != 0x00){
                buff[idx_char_buff] = _url[idx_char_url];
                idx_char_url++;
                idx_char_buff++;
            }
            *_port = (uint16_t) atoi(buff);
        }
        memset(buff, 0x00, 9*sizeof(char));
        if (_url[idx_char_url] == 0x00){
            free(buff);
            buff = NULL;
            return 0x00;
        }
        sub_tmp.stcp_sub_pos = idx_char_url;
        sub_tmp.stcp_sub_size = 0;
        while(_url[idx_char_url] != 0x00){
            idx_char_url++;
            sub_tmp.stcp_sub_size++;
        }
        if (sub_tmp.stcp_sub_size > 0){
            *_end_point = sub_tmp;
        }
        free(buff);
        buff = NULL;
    }
    else {
        stcp_debug(__func__, STCP_DEBUG_ERROR, "undefined protocol (http/https - select one)\n");
        return 0x02;
    }
    return 0x00;
}
#endif

/**
 * Create dinamic allocated string memmory with minimum memmory allocation
 * @param[in] _size_per_allocate an unsigned short of size per allocation
 * @param[in] _str_format a constant character pointer of string format followed by arguments (printf style)
 * @return allocated character pointer if success, NULL if failed
 */
char *stcp_http_content_generator(unsigned short _size_per_allocate, const char *_str_format, ...){
	va_list ar;
	/* var list */
	char *s = NULL;

	char collect_flag = 0x00;
	char format[8];
	char buff_tmp[32];
	unsigned char idx_format = 0;
	unsigned short buff_length = 0;
	unsigned short idx_rfmt = 0;

	char *buff_result = NULL;
	unsigned short result_size = _size_per_allocate;
	unsigned short idx_result = 0;

	buff_result = (char *) malloc(result_size * sizeof(char));
	if(buff_result == NULL){
		return NULL;
	}
	memset(buff_result, 0x00, result_size * sizeof(char));

	va_start(ar, _str_format);
	while(_str_format[idx_rfmt]){
		if (!collect_flag){
			if (_str_format[idx_rfmt] == 0x25){
				collect_flag = 0x01;
				idx_format = 0x01;
				memset(format, 0x00, sizeof(format));
				format[0] = 0x25;
			}
			else {
				buff_result[idx_result] = _str_format[idx_rfmt];
				if (result_size <= idx_result + 2){
					result_size += _size_per_allocate;
					buff_result = (char *) realloc(buff_result, result_size * sizeof(char));
				}
				idx_result++;
				buff_result[idx_result] = 0x00;
			}
		}
		else {
			format[idx_format] = _str_format[idx_rfmt];
			idx_format++;
			if (_str_format[idx_rfmt] < 0x30 || _str_format[idx_rfmt] > 0x39){
				memset(buff_tmp, 0x00, sizeof(buff_tmp));
				switch(_str_format[idx_rfmt]){
					case 's':
						s = va_arg(ar, char *); 
						goto common_operation_str_rfmt;
					case 'd':
						sprintf(buff_tmp, format, va_arg(ar, int));
						s = buff_tmp;
						goto common_operation_str_rfmt;
					case 'i':
						sprintf(buff_tmp, format, va_arg(ar, unsigned int));
						s = buff_tmp;
						goto common_operation_str_rfmt;
					case 'f':
						sprintf(buff_tmp, format, (float) va_arg(ar, double));
						s = buff_tmp;
						goto common_operation_str_rfmt;
					case 'l':
						idx_rfmt++;
						if (_str_format[idx_rfmt] == 'i'){
							format[idx_format] = _str_format[idx_rfmt];
							sprintf(buff_tmp, format, va_arg(ar, long));
							s = buff_tmp;
							goto common_operation_str_rfmt;
						}
						else if (_str_format[idx_rfmt] == 'u'){
							format[idx_format] = _str_format[idx_rfmt];
							sprintf(buff_tmp, format, va_arg(ar, unsigned long));
							s = buff_tmp;
							goto common_operation_str_rfmt;
						}
						else if (_str_format[idx_rfmt] == 'l'){
							format[idx_format] = _str_format[idx_rfmt];
							idx_format++;
							idx_rfmt++;
							if (_str_format[idx_rfmt] == 'i'){
								format[idx_format] = _str_format[idx_rfmt];
								sprintf(buff_tmp, format, va_arg(ar, long long));
								s = buff_tmp;
								goto common_operation_str_rfmt;
							}
							else if (_str_format[idx_rfmt] == 'u'){
								format[idx_format] = _str_format[idx_rfmt];
								sprintf(buff_tmp, format, va_arg(ar, unsigned long long));
								s = buff_tmp;
								goto common_operation_str_rfmt;
							}
							else {
								format[idx_format] = _str_format[idx_rfmt];
								s = format;
								goto common_operation_str_rfmt;
							}
						}
						break;
					case 'c':
						if (result_size <= idx_result + 2){
							result_size += _size_per_allocate;
							buff_result = (char *) realloc(buff_result, result_size * sizeof(char));
						}
						buff_result[idx_result] = (char) va_arg(ar, int);;
						buff_length = 1;
						break;
					default:
						s = format + 1;
						common_operation_str_rfmt:
						buff_length = (unsigned short) strlen(s);
						if(result_size <= idx_result + buff_length + 2){
							result_size += (buff_length + 2);
							buff_result = (char *) realloc(buff_result, result_size * sizeof(char));
						}
						memcpy(buff_result + idx_result, s, buff_length);
						s = NULL;
						break;
				}
				idx_result += buff_length;
				buff_result[idx_result] = 0x00;
				collect_flag = 0x00;
			}
		}
		idx_rfmt++;
	}
	va_end(ar);
	buff_result = (char *) realloc(buff_result, (idx_result + 1)*sizeof(char));
	return buff_result;
}

/**
 * Append or create dinamic allocated string memmory with minimum memmory allocation (append process will be processed if input buffer is not NULL)
 * @param[in] _buff_source a character pointer of input buffer
 * @param[in] _size_per_allocate an unsigned short of size per allocation
 * @param[in] _append_size an unsigned short of size append size (set this field to zero if argument is not NULL or append size is not constant)
 * @param[in] _str_format a constant character pointer of string format followed by arguments (printf style)
 * @return allocated character pointer if success, NULL if failed
 */
char *stcp_http_str_append(
 char *_buff_source,
 unsigned short _size_per_allocate,
 unsigned short _append_size,
 const char *_str_format, ...
){
	char *buff_result = NULL;
	unsigned short result_size = _size_per_allocate;
	unsigned short idx_result = 0;

	buff_result = _buff_source;
	if (buff_result == NULL){
		if (_append_size){
			result_size = _append_size + 1;
			buff_result = (char *) malloc(result_size * sizeof(char));
			if(buff_result == NULL){
				return NULL;
			}
			memcpy(buff_result, _str_format, _append_size);
			buff_result[_append_size] = 0x00;
			return buff_result;
		}
		buff_result = (char *) malloc(result_size * sizeof(char));
		if(buff_result == NULL){
			return NULL;
		}
		memset(buff_result, 0x00, result_size * sizeof(char));
	}
	else {
		idx_result = (unsigned short) strlen(buff_result);
		if (_append_size){
			result_size = idx_result + _append_size + 1;
			buff_result = (char *) realloc(buff_result, result_size * sizeof(char));
			memcpy(buff_result + idx_result, _str_format, _append_size);
			buff_result[result_size - 1] = 0x00;
			return buff_result;
		}
		result_size = idx_result + _size_per_allocate;
		buff_result = (char *) realloc(buff_result, result_size * sizeof(char));
	}

	va_list ar;
	/* var list */
	char *s = NULL;

	char collect_flag = 0x00;
	char format[8];
	char buff_tmp[32];
	unsigned char idx_format = 0;
	unsigned short buff_length = 0;
	unsigned short idx_rfmt = 0;

	va_start(ar, _str_format);
	while(_str_format[idx_rfmt]){
		if (!collect_flag){
			if (_str_format[idx_rfmt] == 0x25){
				collect_flag = 0x01;
				idx_format = 0x01;
				memset(format, 0x00, sizeof(format));
				format[0] = 0x25;
			}
			else {
				buff_result[idx_result] = _str_format[idx_rfmt];
				if (result_size <= idx_result + 2){
					result_size += _size_per_allocate;
					buff_result = (char *) realloc(buff_result, result_size * sizeof(char));
				}
				idx_result++;
				buff_result[idx_result] = 0x00;
			}
		}
		else {
			format[idx_format] = _str_format[idx_rfmt];
			idx_format++;
			if (_str_format[idx_rfmt] < 0x30 || _str_format[idx_rfmt] > 0x39){
				memset(buff_tmp, 0x00, sizeof(buff_tmp));
				switch(_str_format[idx_rfmt]){
					case 's':
						s = va_arg(ar, char *); 
						goto common_operation_str_rfmt;
					case 'd':
						sprintf(buff_tmp, format, va_arg(ar, int));
						s = buff_tmp;
						goto common_operation_str_rfmt;
					case 'i':
						sprintf(buff_tmp, format, va_arg(ar, unsigned int));
						s = buff_tmp;
						goto common_operation_str_rfmt;
					case 'f':
						sprintf(buff_tmp, format, (float) va_arg(ar, double));
						s = buff_tmp;
						goto common_operation_str_rfmt;
					case 'l':
						idx_rfmt++;
						if (_str_format[idx_rfmt] == 'i'){
							format[idx_format] = _str_format[idx_rfmt];
							sprintf(buff_tmp, format, va_arg(ar, long));
							s = buff_tmp;
							goto common_operation_str_rfmt;
						}
						else if (_str_format[idx_rfmt] == 'u'){
							format[idx_format] = _str_format[idx_rfmt];
							sprintf(buff_tmp, format, va_arg(ar, unsigned long));
							s = buff_tmp;
							goto common_operation_str_rfmt;
						}
						else if (_str_format[idx_rfmt] == 'l'){
							format[idx_format] = _str_format[idx_rfmt];
							idx_format++;
							idx_rfmt++;
							if (_str_format[idx_rfmt] == 'i'){
								format[idx_format] = _str_format[idx_rfmt];
								sprintf(buff_tmp, format, va_arg(ar, long long));
								s = buff_tmp;
								goto common_operation_str_rfmt;
							}
							else if (_str_format[idx_rfmt] == 'u'){
								format[idx_format] = _str_format[idx_rfmt];
								sprintf(buff_tmp, format, va_arg(ar, unsigned long long));
								s = buff_tmp;
								goto common_operation_str_rfmt;
							}
							else {
								format[idx_format] = _str_format[idx_rfmt];
								s = format;
								goto common_operation_str_rfmt;
							}
						}
						break;
					case 'c':
						if (result_size <= idx_result + 2){
							result_size += _size_per_allocate;
							buff_result = (char *) realloc(buff_result, result_size * sizeof(char));
						}
						buff_result[idx_result] = (char) va_arg(ar, int);;
						buff_length = 1;
						break;
					default:
						s = format + 1;
						common_operation_str_rfmt:
						buff_length = (unsigned short) strlen(s);
						if(result_size <= idx_result + buff_length + 2){
							result_size += (buff_length + 2);
							buff_result = (char *) realloc(buff_result, result_size * sizeof(char));
						}
						memcpy(buff_result + idx_result, s, buff_length);
						s = NULL;
						break;
				}
				idx_result += buff_length;
				buff_result[idx_result] = 0x00;
				collect_flag = 0x00;
			}
		}
		idx_rfmt++;
	}
	va_end(ar);
	buff_result = (char *) realloc(buff_result, (idx_result + 1)*sizeof(char));
	return buff_result;
}

#ifndef __STCP_DONT_USE_CLIENT__
/**
 * Create new multipart header for HTTP Client Request (style input: general header + multipart/from-data|form_data_1|form_data_2|...|file)
 * @param[in] _stcp_multipart_header_input a constant character pointer of HTTP Request Header
 * @param[out] _boundary_output a character pointer of boundary (example: --stcpmboundaryxxxxxxxxxxxx)
 * @param[out] _length_part an unsigned short pointer of that inform the length of new header that have been produces
 * @return allocated unsigned character pointer if success, NULL if failed
 */
unsigned char *stcp_http_generate_multipart_header(
 const char *_stcp_multipart_header_input,
 char *_boundary_output,
 uint16_t *_length_part
){
    /* style: general_header_end_with_multipart/from-data|form_data_1|form_data_2|...|file */
    /* boundary style : --stcpmboundaryxxxxxxxxxxxx */
    unsigned char *output_header = NULL;
    unsigned char *buff = NULL;
    buff = (unsigned char *) malloc(128 * sizeof(unsigned char));
    if (buff == NULL){
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate buffer memory\n");
        #endif
        return NULL;
    }
    uint16_t idx_header = 0;
    uint16_t pos_header = 0;
    uint16_t header_length = (uint16_t) strlen(_stcp_multipart_header_input);
    uint16_t idx_data = 0;
    uint16_t buff_size = 0;
    uint8_t num_of_from_data = 0;
    uint8_t num_tmp = 0;
    uint8_t content_type_flag = 0x00;
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
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "from-data is missing\n");
        #endif
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
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate header memory\n");
        #endif
        free(buff);
        buff = NULL;
        return NULL;
    }
    memset(buff, 0x00, 32*sizeof(unsigned char));
    sprintf((char *) buff, "--stcpmboundary%012li", stcp_time_boundary);
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
            if (content_type_flag == 0x00){
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
            }
            else {
                if (num_tmp < num_of_from_data){
                    output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 5)*sizeof(unsigned char));
                    memcpy(output_header + pos_header, buff, idx_data);
                    memcpy(output_header + (pos_header + idx_data), "\r\n\r\n", 4);
                    pos_header += idx_data + 4;
                }
                content_type_flag = 0x00;
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
            content_type_flag = 0x00;
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
        else if (_stcp_multipart_header_input[idx_header] == '~' && idx_data > 0){
            content_type_flag = 0x01;
            if (num_tmp == 0 && num_tmp < num_of_from_data){
                output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 4)*sizeof(unsigned char));
                memcpy(output_header + pos_header, buff, idx_data);
                memcpy(output_header + (pos_header + idx_data), "\"\r\n", 3);
                pos_header += idx_data + 3;
            }
            else if (num_tmp < num_of_from_data){
                output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 4 + 27 + 40 + 4)*sizeof(unsigned char));
                memcpy(output_header + pos_header, "\r\n--", 4);
                memcpy(output_header + (pos_header + 4), _boundary_output, 27);
                memcpy(output_header + (pos_header + 4 + 27), "\r\nContent-Disposition: form-data; name=\"", 40);
                memcpy(output_header + (pos_header + 4 + 27 + 40), buff, idx_data);
                memcpy(output_header + (pos_header + 4 + 27 + 40 + idx_data), "\"\r\n", 3);
                pos_header += idx_data + 4 + 27 + 40 + 3;
            }
            else {
                output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 4)*sizeof(unsigned char));
                memcpy(output_header + pos_header, buff, idx_data);
                memcpy(output_header + (pos_header + idx_data), "\"\r\n", 3);
                pos_header += idx_data + 3;
                output_header[pos_header] = 0x00;
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
        else if (_stcp_multipart_header_input[idx_header] == 0x00){
            if (!content_type_flag){
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
            }
            else {
                output_header = (unsigned char *) realloc(output_header, (pos_header + idx_data + 5)*sizeof(unsigned char));
                memcpy(output_header + pos_header, buff, idx_data);
                memcpy(output_header + (pos_header + idx_data), "\r\n\r\n", 4);
                pos_header += idx_data + 4;
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

/**
 * Send HTTP Client Request
 * @param[in] _req_type a constant character pointer of HTTP Request type (GET/POST/PATCH/etc)
 * @param[in] _url a constant character pointer of URL
 * @param[in] _header a constant character pointer of additional field of HTTP Client Request Header (set this field to NULL no additional field available)
 * @param[in] _content a constant character pointer of content/body (set this field to NULL no content/body are available, for example in GET Request)
 * @param[in] _request_type a member of enum on __stcp_request_type__ (you can find this on header file) that will determine the routine process
 * @return allocated unsigned character pointer of http webserver response if success
 * @return NULL if request preparation failed
 * @return allocated unsigned character pointer "no route to host" if failed to connect
 * @return allocated unsigned character pointer "bad connection or bad request" if failed to receive content
 * @return allocated unsigned character pointer "request timeout" if timeout to receive content
 */
unsigned char *stcp_http_request(
 const char *_req_type,
 const char *_url,
 const char *_header,
 const char *_content,
 stcp_request_type _request_type
){
    long request_length = 0;
    if (_request_type != STCP_REQ_UPLOAD_FILE){
        if (_content != NULL){
            request_length = (long) strlen(_content);
        }
    }
    else if (_content != NULL){
        request_length = stcp_get_file_size(_content);
        if (request_length < 0){
            stcp_debug(__func__, STCP_DEBUG_ERROR, "request aborted.\n");
            return NULL;
        }
        else if (request_length == 0){
            stcp_debug(__func__, STCP_DEBUG_WARNING, "file empety.request aborted.\n");
            return NULL;
        }
    }
    else {
        stcp_debug(__func__, STCP_DEBUG_ERROR, "bad STCP request. process aborted.\n");
        return NULL;
    }
    unsigned char *stcp_trx_buffer = NULL;
    unsigned char *response = NULL;
    char *boundary = NULL;
    stcpSHead host = {0, 0};
    stcpSHead end_point = {0 , 0};
    int8_t protocol = 0;
    uint32_t length_of_message = 0;
    uint16_t port = 0;

    FILE *download_file = NULL;
    uint8_t try_times = 0;

    length_of_message = (uint32_t) strlen(_req_type) + 53;
    stcp_trx_buffer = (unsigned char *) malloc((length_of_message + 1) * sizeof(unsigned char));
    if (stcp_trx_buffer == NULL){
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate message variable memory\n");
        return NULL;
    }
    response = (unsigned char *) malloc(2 * sizeof(unsigned char));
    if (response == NULL){
        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate response variable memory\n");
        free(stcp_trx_buffer);
        stcp_trx_buffer = NULL;
        return NULL;
    }
    if (_header != NULL){
        if (strstr(_header, "multipart/form-data") != NULL){
            boundary = (char *) malloc(32 * sizeof(unsigned char));
            if (boundary == NULL){
                stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to allocate response variable memory\n");
                free(stcp_trx_buffer);
                free(response);
                stcp_trx_buffer = NULL;
                response = NULL;
                return NULL;
            }
        }
    }
    int8_t retval = stcp_url_parser(_url, &protocol, &host, &end_point, &port);
    if (retval == -1){
        free(stcp_trx_buffer);
        free(response);
        stcp_trx_buffer = NULL;
        response = NULL;
        if (_header != NULL){
            if (strstr(_header, "multipart/form-data") != NULL){
                free(boundary);
                boundary = NULL;
            }
        }
        return NULL;
    }

    stcpSock http_socket_f;
    /* use stcp_trx_buffer variable for store host_name variable (temporary) to reduce memory allocation */
    memset(stcp_trx_buffer, 0x00, (length_of_message * sizeof(char)));
    memcpy(stcp_trx_buffer, _url + host.stcp_sub_pos, host.stcp_sub_size);
    if (protocol==0){
        http_socket_f = stcp_client_init((char *) stcp_trx_buffer, port);
    }
    else {
        #ifdef __STCP_SSL__
        http_socket_f = stcp_ssl_client_init((char *) stcp_trx_buffer, port);
        #else
        stcp_debug(__func__, STCP_DEBUG_WARNING, "please enable __STCP_SSL__ on shiki-tcp-ip-tools.h\n");
        free(stcp_trx_buffer);
        free(response);
        stcp_trx_buffer = NULL;
        response = NULL;
        if (_header != NULL){
            if (strstr(_header, "multipart/form-data") != NULL){
                free(boundary);
                boundary = NULL;
            }
        }
        return NULL;
        #endif
    }
    if (http_socket_f.socket_f <= 0){
        free(stcp_trx_buffer);
        stcp_trx_buffer = NULL;
        if (_header != NULL){
            if (strstr(_header, "multipart/form-data") != NULL){
                free(boundary);
                boundary = NULL;
            }
        }
        response = (unsigned char *) realloc(response, 17*sizeof(unsigned char));
        memset(response, 0x00, 17*sizeof(unsigned char));
        strncpy((char *) response, "no route to host", 17);
        return response;
    }
    length_of_message = length_of_message + host.stcp_sub_size + end_point.stcp_sub_size;
    if (_header != NULL && _content != NULL){
        char buff[16];
        memset(buff, 0x00, sizeof(buff));
        sprintf(buff, "%li\r\n\r\n", request_length);
        if (_request_type != STCP_REQ_UPLOAD_FILE){
            length_of_message = length_of_message + strlen(_header) + strlen(_content);
            stcp_trx_buffer = (unsigned char *) realloc(stcp_trx_buffer, (length_of_message + 1)*sizeof(unsigned char));
            memset(stcp_trx_buffer, 0x00, (length_of_message + 1)*sizeof(unsigned char));
            sprintf((char *) stcp_trx_buffer, "%s ", _req_type);
            strncat((char *) stcp_trx_buffer, _url + end_point.stcp_sub_pos, end_point.stcp_sub_size);
            strcat((char *) stcp_trx_buffer,
             " HTTP/1.1\r\n"
             "Host: "
            );
            strncat((char *) stcp_trx_buffer, _url + host.stcp_sub_pos, host.stcp_sub_size);
            strcat((char *) stcp_trx_buffer, "\r\n");
            strcat((char *) stcp_trx_buffer, _header);
            strcat((char *) stcp_trx_buffer,
             "\r\n"
             "Content-Length: "
            );
            strcat((char *) stcp_trx_buffer, buff);
            strcat((char *) stcp_trx_buffer, _content);
            strcat((char *) stcp_trx_buffer, "\r\n\r\n");
        }
        else {
            if (strstr(_header, "multipart/form-data") == NULL){
                length_of_message = length_of_message + strlen(_header);
                stcp_trx_buffer = (unsigned char *) realloc(stcp_trx_buffer, (length_of_message + 1)*sizeof(unsigned char));
                memset(stcp_trx_buffer, 0x00, (length_of_message + 1)*sizeof(char));
                sprintf((char *) stcp_trx_buffer, "%s ", _req_type);
                strncat((char *) stcp_trx_buffer, _url + end_point.stcp_sub_pos, end_point.stcp_sub_size);
                strcat((char *) stcp_trx_buffer,
                 " HTTP/1.1\r\n"
                 "Host: "
                );
                strncat((char *) stcp_trx_buffer, _url + host.stcp_sub_pos, host.stcp_sub_size);
                strcat((char *) stcp_trx_buffer, "\r\n");
                strcat((char *) stcp_trx_buffer, _header);
                strcat((char *) stcp_trx_buffer,
                 "\r\n"
                 "Content-Length: "
                );
                strcat((char *) stcp_trx_buffer, buff);
            }
            else {
                uint16_t part_content_length = 0;
                memset(boundary, 0x00, 32*sizeof(char));
                char *header_part = (char *) stcp_http_generate_multipart_header(_header, boundary, &part_content_length);
                if (header_part != NULL){
                    memset(buff, 0x00, sizeof(buff));
                    sprintf(buff, "%li\r\n", request_length + part_content_length + 2);
                    length_of_message = length_of_message + strlen(header_part);
                    stcp_trx_buffer = (unsigned char *) realloc(stcp_trx_buffer, (length_of_message + 1)*sizeof(unsigned char));
                    memset(stcp_trx_buffer, 0x00, (length_of_message + 1)*sizeof(unsigned char));
                    sprintf((char *) stcp_trx_buffer, "%s ", _req_type);
                    strncat((char *) stcp_trx_buffer, _url + end_point.stcp_sub_pos, end_point.stcp_sub_size);
                    strcat((char *) stcp_trx_buffer,
                     " HTTP/1.1\r\n"
                     "Host: "
                    );
                    strncat((char *) stcp_trx_buffer, _url + host.stcp_sub_pos, host.stcp_sub_size);
                    strcat((char *) stcp_trx_buffer,
                     "\r\n"
                     "Content-Length: "
                    );
                    strcat((char *) stcp_trx_buffer, buff);
                    strcat((char *) stcp_trx_buffer, header_part);
                    free(header_part);
                    header_part = NULL;
                }
                else {
                    stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to generate multipart/form-data\n");
                    length_of_message = length_of_message + strlen(_header);
                    stcp_trx_buffer = (unsigned char *) realloc(stcp_trx_buffer, (length_of_message + 1)*sizeof(unsigned char));
                    memset(stcp_trx_buffer, 0x00, (length_of_message + 1)*sizeof(unsigned char));
                    sprintf((char *) stcp_trx_buffer, "%s ", _req_type);
                    strncat((char *) stcp_trx_buffer, _url + end_point.stcp_sub_pos, end_point.stcp_sub_size);
                    strcat((char *) stcp_trx_buffer,
                     " HTTP/1.1\r\n"
                     "Host: "
                    );
                    strncat((char *) stcp_trx_buffer, _url + host.stcp_sub_pos, host.stcp_sub_size);
                    strcat((char *) stcp_trx_buffer, "\r\n");
                    strcat((char *) stcp_trx_buffer, _header);
                    strcat((char *) stcp_trx_buffer,
                     "\r\n"
                     "Content-Length: "
                    );
                    strcat((char *) stcp_trx_buffer, buff);
                    free(boundary);
                    boundary = NULL;
                }
            }
        }
    }
    else if (_content == NULL && _header != NULL){
        length_of_message = length_of_message + strlen(_header);
        stcp_trx_buffer = (unsigned char *) realloc(stcp_trx_buffer, (length_of_message + 1)*sizeof(unsigned char));
        memset(stcp_trx_buffer, 0x00, (length_of_message + 1)*sizeof(unsigned char));
        sprintf((char *) stcp_trx_buffer, "%s ", _req_type);
        strncat((char *) stcp_trx_buffer, _url + end_point.stcp_sub_pos, end_point.stcp_sub_size);
        strcat((char *) stcp_trx_buffer,
         " HTTP/1.1\r\n"
         "Host: "
        );
        strncat((char *) stcp_trx_buffer, _url + host.stcp_sub_pos, host.stcp_sub_size);
        strcat((char *) stcp_trx_buffer, "\r\n");
        strcat((char *) stcp_trx_buffer, _header);
        strcat((char *) stcp_trx_buffer, "\r\n\r\n");
    }
    else if (_header == NULL){
        stcp_trx_buffer = (unsigned char *) realloc(stcp_trx_buffer, (length_of_message + 1)*sizeof(unsigned char));
        memset(stcp_trx_buffer, 0x00, (length_of_message + 1)*sizeof(unsigned char));
        sprintf((char *) stcp_trx_buffer, "%s ", _req_type);
        strncat((char *) stcp_trx_buffer, _url + end_point.stcp_sub_pos, end_point.stcp_sub_size);
        strcat((char *) stcp_trx_buffer,
         " HTTP/1.1\r\n"
         "Host: "
        );
        strncat((char *) stcp_trx_buffer, _url + host.stcp_sub_pos, host.stcp_sub_size);
        strcat((char *) stcp_trx_buffer, "\r\n\r\n");
    }
    stcp_debug(__func__, STCP_DEBUG_INFO, "HTTP Request:\n");
    if (stcp_setup_data.stcp_debug_mode == STCP_DEBUG_ON){
        printf("%s\n", stcp_trx_buffer);
    }

    if (_request_type == STCP_REQ_DOWNLOAD_CONTENT){
        if (strlen(stcp_file_name) == 0){
            char stcp_file_name_tmp[sizeof(stcp_file_name)];
            uint16_t idx_stcp_file_name = 0;
            memset(stcp_file_name, 0x00, sizeof(stcp_file_name));
            memset(stcp_file_name_tmp, 0x00, sizeof(stcp_file_name_tmp));
            for (idx_stcp_file_name = 0; idx_stcp_file_name<end_point.stcp_sub_size; idx_stcp_file_name++){
                if (_url[(end_point.stcp_sub_pos + end_point.stcp_sub_size) - 1 - idx_stcp_file_name] == '/' ||
                 idx_stcp_file_name == STCP_MAX_LENGTH_FILE_NAME - 1
                ){
                    break;
                }
                stcp_file_name_tmp[idx_stcp_file_name] = _url[(end_point.stcp_sub_pos + end_point.stcp_sub_size) - 1 - idx_stcp_file_name];
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
            stcp_debug(__func__, STCP_DEBUG_WARNING, "file already exist. process: remove existing file\n");
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

    if (protocol == 0){
        stcp_send_data(http_socket_f, stcp_trx_buffer, strlen((char *) stcp_trx_buffer));
        if (_request_type == STCP_REQ_UPLOAD_FILE){
            stcp_send_file(http_socket_f, _content);
            if (strstr(_header, "multipart/form-data") != NULL && boundary != NULL){
                char *endboundary = stcp_http_content_generator(64, "\r\n--%s--\r\n", boundary);
                if (endboundary != NULL){
                    stcp_send_data(http_socket_f, (unsigned char *) endboundary, strlen(endboundary));
                    free(endboundary);
                    endboundary = NULL;
                }
                else {
                    stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to create end boundary\n");
                }if (boundary != NULL){
                    free(boundary);
                    boundary = NULL;
                }
            }
        }
    }
    else {
        #ifdef __STCP_SSL__
        stcp_ssl_send_data(http_socket_f, (unsigned char *) stcp_trx_buffer, strlen((char *) stcp_trx_buffer));
        if (_request_type == STCP_REQ_UPLOAD_FILE){
            stcp_ssl_send_file(http_socket_f, _content);
            if (strstr(_header, "multipart/form-data") != NULL && boundary != NULL){
                char *endboundary = stcp_http_content_generator(64, "\r\n--%s--\r\n", boundary);
                if (endboundary != NULL){
                    stcp_ssl_send_data(http_socket_f, (unsigned char *) endboundary, strlen(endboundary));
                    free(endboundary);
                    endboundary = NULL;
                }
                else {
                    stcp_debug(__func__, STCP_DEBUG_WARNING, "failed to create end boundary\n");
                }
                if (boundary != NULL){
                    free(boundary);
                    boundary = NULL;
                }
            }
        }
        #endif
    }
    
    int32_t bytes = 0;
    uint32_t total_bytes = 0;
    uint32_t total_bytes_tmp = 0;
    int8_t header_check_status = STCP_HEADER_CHECK;
    int8_t get_process = STCP_PROCESS_GET_HEADER;
    uint32_t content_length = 0;
    uint32_t download_counter = 0;
    uint8_t recv_trytimes = 0;
    int8_t transfer_encoding = 0;

    stcp_trx_buffer = (unsigned char *) realloc(stcp_trx_buffer, (stcp_setup_data.stcp_size_per_recv + 1) * sizeof(unsigned char));
    memset(response, 0x00, 2 * sizeof(char));
    if (_request_type == STCP_REQ_UPLOAD_FILE) {
        _request_type = STCP_REQ_CONTENT_ONLY;
    }
    do {
        memset(stcp_trx_buffer, 0x00, stcp_setup_data.stcp_size_per_recv + 1);
        if (protocol == 0){
            bytes = stcp_recv_data(http_socket_f, stcp_trx_buffer, stcp_setup_data.stcp_size_per_recv);
        }
        else {
            #ifdef __STCP_SSL__
            bytes = stcp_ssl_recv_data(http_socket_f, stcp_trx_buffer, stcp_setup_data.stcp_size_per_recv);
            #endif
        }
        if (bytes == -1){
            stcp_debug(__func__, STCP_DEBUG_ERROR, "Lost Connection\n");
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
            stcp_debug(__func__, STCP_DEBUG_INFO, "reset recv try counter to zero\n");
            recv_trytimes = 0;
        }
        if (_request_type != STCP_REQ_DOWNLOAD_CONTENT || get_process == STCP_PROCESS_GET_HEADER){
            total_bytes_tmp = total_bytes_tmp + bytes;
            response = (unsigned char *) realloc(response, (total_bytes + bytes + 1) * sizeof(unsigned char));
            memcpy(response + total_bytes, stcp_trx_buffer, bytes);
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
                        else if (_request_type == STCP_REQ_HTTP_STATUS_ONLY){
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
                                        stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to open config file\n");
                                    }
                                    else {
                                        memset(stcp_trx_buffer, 0x00, (stcp_setup_data.stcp_size_per_recv + 1)*sizeof(char));
                                        memcpy(stcp_trx_buffer, response + total_bytes, bytes);
                                        fwrite(stcp_trx_buffer, 1, bytes, download_file);
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
                    stcp_debug(__func__, STCP_DEBUG_INFO, "get: %i/%i bytes\n", download_counter, content_length);
                }
                else{
                    if(response[total_bytes - 1] == '\n' && response[total_bytes - 2] == '\r' &&
                     response[total_bytes - 3] == '\n' && response[total_bytes - 4] == '\r' &&
                     transfer_encoding == 1
                    ){
                        stcp_debug(__func__, STCP_DEBUG_INFO, "get: %i/unknown bytes - finished\n", download_counter);
                        break;
                    }
                    stcp_debug(__func__, STCP_DEBUG_INFO, "get: %i/unknown bytes\n", download_counter);
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
                    stcp_debug(__func__, STCP_DEBUG_INFO, "downloaded: %i/%i bytes\n", download_counter, content_length);
                }
                else {
                    stcp_debug(__func__, STCP_DEBUG_INFO, "downloaded: %i/unknown bytes\n", download_counter);
                }
            }

            /* append file */
            if (download_file == NULL){
                stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to open config file\n");
            }
            else {
                fwrite(stcp_trx_buffer, 1, bytes, download_file);
            }
        }

        if (content_length > 0 && download_counter == content_length){
            break;
        }

        try_recv:
            if(bytes == 0){
                stcp_debug(__func__, STCP_DEBUG_WARNING, "try recv process (%i/%i)\n", recv_trytimes, stcp_setup_data.stcp_max_recv_try);
            }
    } while (bytes >= 0);

    request_finished:
        if (protocol == 0){
            stcp_close(&http_socket_f);
        }
        else {
            #ifdef __STCP_SSL__
            stcp_ssl_close(&http_socket_f);
            #endif
        }
        if (_request_type == STCP_REQ_DOWNLOAD_CONTENT){
            memset(stcp_file_name, 0x00, sizeof(stcp_file_name));
            if (download_file != NULL){
                fclose(download_file);
            }
            if (content_length > 0){
                if (download_counter == content_length){
                    stcp_debug(__func__, STCP_DEBUG_DOWNLOAD, "downloaded finished: %i/%i bytes\n", download_counter, content_length);
                }
                else {
                    stcp_debug(__func__, STCP_DEBUG_DOWNLOAD, "downloaded unfinished: %i/%i bytes\n", download_counter, content_length);
                }
            }
            else {
                stcp_debug(__func__, STCP_DEBUG_DOWNLOAD, "downloaded finished: %i/unknown bytes\n", __func__, download_counter);
            }
        }
        free(stcp_trx_buffer);
        stcp_trx_buffer = NULL;
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
#endif

/**
 * Close and release TCP/IP socket informations
 * @param[in] init_data __stcpSock__ pointer of socket informations
 */
void stcp_close(stcpSock *init_data){
    if(init_data->socket_f == init_data->connection_f){
        if (init_data->socket_f > 0){
            close(init_data->socket_f);
        }
        init_data->socket_f = -1;
    }
    else{
        if (init_data->connection_f > 0){
            close(init_data->connection_f);
        }
        if (init_data->socket_f > 0){
            close(init_data->socket_f);
        }
        init_data->connection_f = -1;
        init_data->socket_f = -1;
    }
}

#ifdef __STCP_SSL__
/**
 * Close and release SSL/TLS socket informations
 * @param[in] init_data __stcpSock__ pointer of socket informations
 */
void stcp_ssl_close(stcpSock *init_data){
    if(init_data->socket_f == init_data->connection_f){
        if (init_data->ssl_connection_f != NULL){
            SSL_shutdown(init_data->ssl_connection_f);
            SSL_free(init_data->ssl_connection_f);
        }
        if (init_data->socket_f > 0){
            close(init_data->socket_f);
        }
        init_data->ssl_connection_f = NULL;
        init_data->socket_f = -1;
    }
    else{
        if (init_data->ssl_connection_f != NULL){
            SSL_shutdown(init_data->ssl_connection_f);
            SSL_free(init_data->ssl_connection_f);
        }
        if (init_data->connection_f > 0){
            close(init_data->connection_f);
        }
        if (init_data->socket_f){
            close(init_data->socket_f);
        }
        init_data->ssl_connection_f = NULL;
        init_data->connection_f = -1;
        init_data->socket_f = -1;
    }
}
#endif

/**
 * Get content length of HTTP Client data (header + content/body)
 * @param[in] _text_source a constant character pointer of HTTP Client data (header + content/body)
 * @return content length
 */
static unsigned long stcp_get_content_length(const char *_text_source){
    char *buff_info = NULL;
    buff_info = (char *) strstr(_text_source, "Content-Length: ");
    if (buff_info == NULL) {
        return 0;
    }
    buff_info += 16;
    char buff_data[16];
    uint8_t idx_data = 0x00;
    for (idx_data = 0x00; idx_data < 15; idx_data++){
        if (idx_data > 0 && (buff_info[idx_data] < '0' || buff_info[idx_data] > '9')){
            buff_data[idx_data] = 0x00;
            return (unsigned long) atol(buff_data);
        }
        else {
            buff_data[idx_data] = buff_info[idx_data];
        }
    }
    return (unsigned long) atol(buff_data);
}

/**
 * Get/select content/body from HTTP Client data (header + content/body)
 * @param[in, out] response an unsigned character pointer of HTTP Client data (header + content/body)
 * @param[in] _content_length an unsigned long integer (32 bits) of content/body length
 * @return content/body of HTTP Client if success
 * @return NULL if _content_length is 0
 * 
 */
static unsigned char *stcp_select_content(
 unsigned char *response,
 uint32_t _content_length
){
    if (_content_length == 0){
        free(response);
        response = NULL;
        return NULL;
    }
    char *buff_tmp = NULL;
    buff_tmp = strstr((char *) response, "\r\n\r\n");
    buff_tmp += 4;
    uint32_t i = 0;
    for (i = 0; i <_content_length; i++){
        response[i] = buff_tmp[i];
    }
    response[_content_length] = 0x00;
    response = (unsigned char *) realloc(response, _content_length + 1);
    return response;
}

/*
PING PURPOSE
run_without_root (do on shell) : setcap cap_net_raw+ep executable_file
*/
#ifdef __STCP_PING__
/**
 * Get checksum of ping data
 * @param[in] b a void pointer of received packet
 * @param[in] len an integer parameter of packet size
 * @return checksum CRC32
 * 
 */
static unsigned short stcp_checksum(void *b, int len){
	unsigned short *buff = (unsigned short *) b;
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

/**
 * Get PING statistics
 * @param[in] ADDRESS a constant character pointer of host/address
 * @param[in] NUM_OF_PING an unsigned short integer parameter that inform the number of ping request
 * @return PING statistics
 * 
 */
struct stcp_ping_summary stcp_ping(const char *ADDRESS, uint16_t NUM_OF_PING){
    stcpSock init_data;
    struct sockaddr_in servaddr;

    const int16_t PACKET_SIZE = 64;
    const uint16_t PING_DELAY = 1000;
    char ip_address[16];

    struct stcp_ping_summary ping_data;
    memset(&ping_data, 0x00, sizeof(struct stcp_ping_summary));

    init_data.socket_f = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (init_data.socket_f == -1) {
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_CRITICAL, "socket creation failed...\n");
        #endif
        ping_data.state = -1;
        return ping_data;
    }
    else{
        #ifdef __STCP_DEBUG__
        stcp_debug(__func__, STCP_DEBUG_INFO, "Socket successfully created : %d\n", init_data.socket_f);
        #endif
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
                stcp_debug(__func__, STCP_DEBUG_ERROR, "failed to get host by name\n", ADDRESS);
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
	int16_t ttl_val = (int16_t)PACKET_SIZE, msg_count = 0;
    size_t i = 0;
    int16_t bytes = 0;
	long double total_tm_ping;
	socklen_t addr_len;

	tv_out.tv_sec = 2;
	tv_out.tv_usec = 0;

    gettimeofday(&tc_start, NULL);

	if (setsockopt(init_data.socket_f, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) 
	{
        #ifdef __STCP_DEBUG__
		stcp_debug(__func__, STCP_DEBUG_CRITICAL, "Setting socket options to TTL failed!\n");
        #endif
	}
	else
	{
        #ifdef __STCP_DEBUG__
		stcp_debug(__func__, STCP_DEBUG_INFO, "Socket set to TTL\n");
        #endif
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
			stcp_debug(__func__, STCP_DEBUG_CRITICAL, "Packet Sending Failed!\n"); 
		} 
		/* receive packet */
		else if ((bytes = recvfrom(init_data.socket_f, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len)) <= 0 && msg_count>1) 
		{
            ping_data.tx_counter++;
			stcp_debug(__func__, STCP_DEBUG_CRITICAL, "Packet receive failed!\n");
		}
		else {
            ping_data.tx_counter++;
			gettimeofday(&tm_end, NULL);
			total_tm_ping = (tm_end.tv_sec - tm_start.tv_sec)*1000.0;
			total_tm_ping = total_tm_ping + (tm_end.tv_usec - tm_start.tv_usec)/1000.0;

			if(pckt.hdr.type!=69)
			{
				stcp_debug(__func__, STCP_DEBUG_CRITICAL, "Error..Packet received with ICMP type %d code %d\n", pckt.hdr.type, pckt.hdr.code);
			}
            else if(pckt.hdr.code!=0){
                stcp_debug(__func__, STCP_DEBUG_WARNING, "packet received (%d) with ICMP type %d code %d : %Lfms\n", bytes, pckt.hdr.type, pckt.hdr.code, total_tm_ping);
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
				stcp_debug(__func__, STCP_DEBUG_INFO, "%d bytes from (%s) msg_seq=%d ttl=%d rtt = %Lf ms\n", PACKET_SIZE, ip_address, msg_count, ttl_val, total_tm_ping);
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

    stcp_debug(__func__, STCP_DEBUG_INFO, "\n"
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