#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shiki-tcp-ip-userdef.h"

#define userpasscode "uname=delameta-enco&psw=b1l4n0"

int8_t stcp_http_webserver_home(stcpSock _init_data, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList _stcpWList){
    SHLinkCustomData _data;
    if (shilink_search_data_by_position(_stcpWList, _stcpWI->ipaddr, 0, &_data) != 0){
        if (strcmp(userpasscode, _stcpWI->rcv_content) != 0){
            char *buffer_info = NULL;
            if (stcp_http_webserver_generate_header(
             _stcpWI,
             "401 Unauthorized",
             _stcpWH->content_type,
             _stcpWH->accept_type,
             0) != 0
            ){
                return -2;
            }
            buffer_info = stcp_http_content_generator(
             1024,
             "%sunauthorized!\r\n", _stcpWI->server_header
            );
            if (buffer_info == NULL){
                stcp_debug(__func__, "ERROR", "unauthorized\n");
                return -2;
            }
            stcp_send_data(_init_data, (unsigned char *) buffer_info, strlen(buffer_info));
            free(buffer_info);
            buffer_info = NULL;
            return 0;
        }
        else {
            shilink_fill_custom_data(&_data, _stcpWI->ipaddr, userpasscode, SL_TEXT);
            shilink_append(&_stcpWList, _data);
        }
    }
    return stcp_http_webserver_send_file(_init_data, _stcpWI, _stcpWH, "200 OK", "webservice/home.html");
}

int8_t stcp_http_webserver_logout(stcpSock _init_data, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList _stcpWList){
    SHLinkCustomData _data;
    if (shilink_search_data_by_position(_stcpWList, _stcpWI->ipaddr, 0, &_data) != 0){
        if (strcmp(userpasscode, _stcpWI->rcv_content) != 0){
            char *buffer_info = NULL;
            if (stcp_http_webserver_generate_header(
             _stcpWI,
             "401 Unauthorized",
             _stcpWH->content_type,
             _stcpWH->accept_type,
             0) != 0
            ){
                return -2;
            }
            buffer_info = stcp_http_content_generator(
             1024,
             "%sunauthorized!\r\n", _stcpWI->server_header
            );
            if (buffer_info == NULL){
                stcp_debug(__func__, "ERROR", "unauthorized\n");
                return -2;
            }
            stcp_send_data(_init_data, (unsigned char *) buffer_info, strlen(buffer_info));
            free(buffer_info);
            buffer_info = NULL;
            return 0;
        }
        else {
            shilink_fill_custom_data(&_data, _stcpWI->ipaddr, userpasscode, SL_TEXT);
            shilink_append(&_stcpWList, _data);
        }
    }
    shilink_delete(&_stcpWList, _data);
    return stcp_http_webserver_send_file(_init_data, _stcpWI, _stcpWH, "200 OK", "webservice/login.html");
}

int8_t stcp_http_webserver_function_select(stcpSock _init_data, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList _stcpWList, char *_response_code, char *_func_name){
    if (strcmp(_func_name, "home") == 0){
        return stcp_http_webserver_home(_init_data, _stcpWI, _stcpWH, _stcpWList);
    }
    else if (strcmp(_func_name, "logout") == 0){
        return stcp_http_webserver_logout(_init_data, _stcpWI, _stcpWH, _stcpWList);
    }
    return 0;
}