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
#define SA struct sockaddr

static void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...);

static void stcp_debug(const char *function_name, char *debug_type, char *debug_msg, ...){
	time_t debug_time;
	struct tm *d_tm;
	char time_str[25];
	va_list aptr;
		
	time(&debug_time);
	d_tm = localtime(&debug_time);
	memset(time_str, 0x00, 25*sizeof(char));
	sprintf(time_str, "%d-%d-%d %d:%d:%d", d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec);
	
	char tmp_debug_msg[100];
	va_start(aptr, debug_msg);
	vsprintf(tmp_debug_msg, debug_msg, aptr);
	va_end(aptr);
	
	printf("%s %s: %s: %s", time_str, debug_type, function_name, tmp_debug_msg);
}

struct stcp_sock_data stcp_server_init(char *ADDRESS, int PORT, int infinite_retry_mode){
    struct stcp_sock_data init_data;
    socklen_t len;
    int retval = 0;
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
            servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
            servaddr.sin_port = htons(PORT);
  
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
    return init_data;
}

struct stcp_sock_data stcp_client_init(char *ADDRESS, int PORT, int infinite_retry_mode){
    struct stcp_sock_data init_data;
    socklen_t len;
    int retval = 0;
    struct sockaddr_in servaddr, cli;
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
            servaddr.sin_addr.s_addr = inet_addr(ADDRESS);
            servaddr.sin_port = htons(PORT);

            stcp_debug(__func__, "INFO", "waiting for server...\n");
            while (connect(init_data.socket_f, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
                sleep(1); 
            }
            init_data.connection_f = init_data.socket_f;
	        stcp_debug(__func__, "INFO", "connected to the server..\n");
        }
    } while (retval < 0 && infinite_retry_mode == 0);
    return init_data;
}

int stcp_send_data(struct stcp_sock_data com_data, char* buff){
    int bytes;
    bytes = write(com_data.connection_f, buff, sizeof(buff));
    stcp_debug(__func__, "INFO", "success to send %d data\n", bytes);
    return bytes;
}

int stcp_recv_data(struct stcp_sock_data com_data, char* buff, int size_set){
    int bytes;
    bytes = read(com_data.connection_f, buff, size_set);
    stcp_debug(__func__, "INFO", "success to receive %d data\n", bytes);
    for (int i=0; i<bytes; i++){
        printf("%02X ", buff[i]);
    }
    printf("\n");
    return bytes;
}

void stcp_close(struct stcp_sock_data init_data){
    if(init_data.socket_f == init_data.connection_f){
        close(init_data.socket_f);
    }
    else{
        close(init_data.connection_f);
        close(init_data.socket_f);
    }
}