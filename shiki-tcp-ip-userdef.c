#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shiki-tcp-ip-userdef.h"

#define userpasscode "uname=delameta-enco&psw=b1l4n0"

int8_t stcp_http_webserver_home_content(stcpSock _init_data, stcpWInfo *_stcpWI){
    char _file_name[] = "seb_tsc_boot.conf";
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
         "200 OK",
         "text/html",
         "none",
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
        stcp_send_data(_init_data, (unsigned char *) buffer_info, strlen(buffer_info));
        free(buffer_info);
        buffer_info = NULL;
        return -2;
    }

    if (stcp_http_webserver_generate_header(
     _stcpWI,
     "200 OK",
     "text/html",
     "none",
     0) != 0
    ){
        fclose(stcp_file);
        return -1;
    }

    unsigned char *file_content = NULL;
    uint16_t SIZE_PER_RECV = 512;
    file_content = (unsigned char *) malloc(SIZE_PER_RECV * sizeof(char));
    if (file_content == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate memory for file_content\n");
        fclose(stcp_file);
        return -3;
    }

    stcp_send_data(_init_data, (unsigned char *) _stcpWI->server_header, strlen(_stcpWI->server_header));

    char *buff_init = NULL;
    buff_init = (char *) malloc(8*sizeof(char));
    if (buff_init == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate buff_init memory\n");
        free(file_content);
        file_content = NULL;
        fclose(stcp_file);
        return -2;
    }

    char *buff_conf;
    buff_conf = (char *) malloc(8*sizeof(char));
    if (buff_conf == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate buff_conf memory\n");
        free(file_content);
        free(buff_init);
        file_content = NULL;
        buff_init = NULL;
        fclose(stcp_file);
        return -2;
    }

	char character = 0;
	uint16_t idx_char = 0;
	int8_t idx_conf = 0;
    int8_t additional_info_flag = 0;
    uint16_t conf_size = 8;
    uint16_t content_size = 0;

    char separator = '=';

	memset(buff_init, 0x00, conf_size*sizeof(char));
	memset(buff_conf, 0x00, conf_size*sizeof(char));

	while((character = fgetc(stcp_file)) != EOF){
		if (character > 127 || character < 9) break;
        if (additional_info_flag == 0){
		    if (character == '\n'){
                if (strcmp(buff_init, "[END]") == 0){
                    additional_info_flag = 1;
                    break;
                }

                sprintf((char *) file_content, 
                 "<div class=\"content-data\">"
                  "<div class=\"content-desc\">"
                   "%s"
                  "</div>"
                  "<div class=\"content-val\">"
                   "%s"
                  "</div>"
                 "</div>",
                 buff_init,
                 buff_conf
                );

                if(stcp_send_data(_init_data, file_content, strlen((char *) file_content)) < 0){
                    break;
                }

		    	memset(buff_init, 0x00, (strlen(buff_init) + 1)*sizeof(char));
		    	memset(buff_conf, 0x00, (strlen(buff_conf) + 1)*sizeof(char));
                conf_size = 8;
		    	idx_conf=idx_char=0;
                buff_init = (char *) realloc(buff_init, conf_size*sizeof(char));
                buff_conf = (char *) realloc(buff_conf, conf_size*sizeof(char));
		    }
		    else if(idx_conf==0 && character != separator){
                if(conf_size < (idx_char + 2)){
                    conf_size = conf_size + 8;
                    buff_init = (char *) realloc(buff_init, conf_size*sizeof(char));
                }
                buff_init[idx_char] = character;
                buff_init[idx_char + 1] = 0x00;
		    	idx_char++;
		    }
		    else if(idx_conf==1 && character != separator){
		    	if(conf_size < (idx_char + 2)){
                    conf_size = conf_size + 8;
                    buff_conf = (char *) realloc(buff_conf, conf_size*sizeof(char));
                }
                buff_conf[idx_char] = character;
                buff_conf[idx_char + 1] = 0x00;
                idx_char++;
		    }
		    else if(character == separator){
		    	idx_char = 0;
		    	idx_conf = 1;
                conf_size = 8;
		    }
        } else {
            if(conf_size < (idx_char + 2)){
                conf_size = conf_size + 8;
                buff_init = (char *) realloc(buff_init, conf_size*sizeof(char));
            }
            buff_init[idx_char] = character;
            buff_init[idx_char + 1] = 0x00;
		    idx_char++;
        }
	}
    free(file_content);
    free(buff_init);
    free(buff_conf);
    file_content = NULL;
    buff_init = NULL;
    buff_conf = NULL;
    fclose(stcp_file);
    return 0;
}

int8_t stcp_http_webserver_conf_setup(stcpSock _init_data, stcpWInfo *_stcpWI){
    char _file_name[] = "seb_tsc_boot.conf";
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
         "200 OK",
         "text/html",
         "none",
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
        stcp_send_data(_init_data, (unsigned char *) buffer_info, strlen(buffer_info));
        free(buffer_info);
        buffer_info = NULL;
        return -2;
    }

    if (stcp_http_webserver_generate_header(
     _stcpWI,
     "200 OK",
     "text/html",
     "none",
     0) != 0
    ){
        fclose(stcp_file);
        return -1;
    }

    unsigned char *file_content = NULL;
    uint16_t SIZE_PER_RECV = 512;
    file_content = (unsigned char *) malloc(SIZE_PER_RECV * sizeof(char));
    if (file_content == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate memory for file_content\n");
        fclose(stcp_file);
        return -3;
    }

    stcp_send_data(_init_data, (unsigned char *) _stcpWI->server_header, strlen(_stcpWI->server_header));

    char *buff_init = NULL;
    buff_init = (char *) malloc(8*sizeof(char));
    if (buff_init == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate buff_init memory\n");
        free(file_content);
        file_content = NULL;
        fclose(stcp_file);
        return -2;
    }

    char *buff_conf;
    buff_conf = (char *) malloc(8*sizeof(char));
    if (buff_conf == NULL){
        stcp_debug(__func__, "ERROR", "failed to allocate buff_conf memory\n");
        free(file_content);
        free(buff_init);
        file_content = NULL;
        buff_init = NULL;
        fclose(stcp_file);
        return -2;
    }

	char character = 0;
	uint16_t idx_char = 0;
	int8_t idx_conf = 0;
    int8_t additional_info_flag = 0;
    uint16_t conf_size = 8;
    uint16_t content_size = 0;

    char separator = '=';

	memset(buff_init, 0x00, conf_size*sizeof(char));
	memset(buff_conf, 0x00, conf_size*sizeof(char));

	while((character = fgetc(stcp_file)) != EOF){
		if (character > 127 || character < 9) break;
        if (additional_info_flag == 0){
		    if (character == '\n'){
                if (strcmp(buff_init, "[END]") == 0){
                    additional_info_flag = 1;
                    break;
                }

                sprintf((char *) file_content, 
                 "<div class=\"content-data\">"
                  "<div class=\"content-desc\">"
                   "%s"
                  "</div>"
                  "<div class=\"content-val\">"
                    "<input class=\"val-input\" type=\"text\" value=\"%s\">"
                  "</div>"
                 "</div>",
                 buff_init,
                 buff_conf
                );

                if(stcp_send_data(_init_data, file_content, strlen((char *) file_content)) < 0){
                    break;
                }

		    	memset(buff_init, 0x00, (strlen(buff_init) + 1)*sizeof(char));
		    	memset(buff_conf, 0x00, (strlen(buff_conf) + 1)*sizeof(char));
                conf_size = 8;
		    	idx_conf=idx_char=0;
                buff_init = (char *) realloc(buff_init, conf_size*sizeof(char));
                buff_conf = (char *) realloc(buff_conf, conf_size*sizeof(char));
		    }
		    else if(idx_conf==0 && character != separator){
                if(conf_size < (idx_char + 2)){
                    conf_size = conf_size + 8;
                    buff_init = (char *) realloc(buff_init, conf_size*sizeof(char));
                }
                buff_init[idx_char] = character;
                buff_init[idx_char + 1] = 0x00;
		    	idx_char++;
		    }
		    else if(idx_conf==1 && character != separator){
		    	if(conf_size < (idx_char + 2)){
                    conf_size = conf_size + 8;
                    buff_conf = (char *) realloc(buff_conf, conf_size*sizeof(char));
                }
                buff_conf[idx_char] = character;
                buff_conf[idx_char + 1] = 0x00;
                idx_char++;
		    }
		    else if(character == separator){
		    	idx_char = 0;
		    	idx_conf = 1;
                conf_size = 8;
		    }
        } else {
            if(conf_size < (idx_char + 2)){
                conf_size = conf_size + 8;
                buff_init = (char *) realloc(buff_init, conf_size*sizeof(char));
            }
            buff_init[idx_char] = character;
            buff_init[idx_char + 1] = 0x00;
		    idx_char++;
        }
	}
    free(file_content);
    free(buff_init);
    free(buff_conf);
    file_content = NULL;
    buff_init = NULL;
    buff_conf = NULL;
    fclose(stcp_file);
    return 0;
}

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

int8_t stcp_select_func(stcpSock _init_data, stcpWInfo *_stcpWI){
    uint16_t size_buff = strlen(_stcpWI->ipaddr) + strlen(_stcpWI->rcv_header) + 3;
    char buff_send[size_buff];
    memset(buff_send, 0x00, sizeof(buff_send));
    sprintf(buff_send, "%s:%s\n", _stcpWI->ipaddr, _stcpWI->rcv_header);
    if (stcp_send_data(_init_data, (unsigned char *) buff_send, strlen(buff_send)) == strlen(buff_send)){
        return 0;
    }
    return -1;
}

int8_t stcp_enco_deduct(stcpSock _init_data, stcpWInfo *_stcpWI){
    uint16_t size_buff = strlen(_stcpWI->ipaddr) + strlen(_stcpWI->rcv_header) + 3;
    char buff_send[size_buff];
    memset(buff_send, 0x00, sizeof(buff_send));
    sprintf(buff_send, "%s:%s\n", _stcpWI->ipaddr, _stcpWI->rcv_header);
    if (stcp_send_data(_init_data, (unsigned char *) buff_send, strlen(buff_send)) == strlen(buff_send)){
        return 0;
    }
    return -1;
}

int8_t stcp_http_webserver_function_select(stcpSock _init_data, stcpWInfo *_stcpWI, stcpWHead *_stcpWH, stcpWList _stcpWList, char *_response_code, char *_func_name){
    int8_t retval = 0;
    if (strcmp(_func_name, "home") == 0){
        retval = stcp_http_webserver_home(_init_data, _stcpWI, _stcpWH, _stcpWList);
        if (retval == 0){
            return 1;
        }
    }
    else if (strcmp(_func_name, "logout") == 0){
        retval = stcp_http_webserver_logout(_init_data, _stcpWI, _stcpWH, _stcpWList);
        if (retval == 0){
            return 1;
        }
    }
    else if (strcmp(_func_name, "config-content") == 0){
        retval = stcp_http_webserver_home_content(_init_data, _stcpWI);
        if (retval == 0){
            return 1;
        }
    }
    else if (strcmp(_func_name, "config-setup") == 0){
        retval = stcp_http_webserver_conf_setup(_init_data, _stcpWI);
        if (retval == 0){
            return 1;
        }
    }
    else if (strcmp(_func_name, "stcp_select_func") == 0){
        retval = stcp_select_func(_init_data, _stcpWI);
        if (retval == 0){
            return 1;
        }
    }
    else if (strcmp(_func_name, "enco-deduct") == 0){
        retval = stcp_select_func(_init_data, _stcpWI);
        if (retval == 0){
            return 1;
        }
    }
    return retval;
}