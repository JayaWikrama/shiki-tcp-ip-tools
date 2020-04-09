#ifndef __SHIKI_TCP_IP_USERDEF__
#define __SHIKI_TCP_IP_USERDEF__
#include <stdint.h>
#include "shiki-tcp-ip-tools.h"

int8_t stcp_http_webserver_function_select(stcpSock _init_data, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList _stcpWList, char *_response_code, char *_func_name);

#endif