#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include "shiki-tcp-ip-tools.h"

int main(){
    stcp_setup(STCP_SET_TIMEOUT, 1);
    stcp_setup(STCP_SET_DEBUG_MODE, STCP_DEBUG_ON);
    stcp_setup(STCP_SET_SIZE_PER_RECV, 64);

    char host[] = "api.telegram.org";
    char header[] = "Content-Type: application/json";
    char end_point[] = "bot1007413403:AAHfALG30Bc4U0h_o1mNqUu-51AD105ggWU/sendMessage";
    
    printf("test http post:\n%s\n", stcp_http_post(host, 80, end_point, header,
     "{\"chat_id\": \"1030198712\", \"text\": \"Akhirnya jadi juga library stcp\"}",
     STCP_REQ_COMPLETE
    ));
    
    printf("test http get:\n%s\n", stcp_http_get(host, 80, end_point, header,
     "{\"chat_id\": \"1030198712\", \"text\": \"Akhirnya jadi juga library stcp\"}",
     STCP_REQ_COMPLETE
    ));

    printf("test https post:\n%s\n", stcp_https_post(host, 443, end_point, header,
     "{\"chat_id\": \"1030198712\", \"text\": \"Akhirnya jadi juga library stcp\"}",
     STCP_REQ_COMPLETE
    ));
    
    printf("test https get:\n%s\n", stcp_https_get(host, 80, end_point, header,
     "{\"chat_id\": \"1030198712\", \"text\": \"Akhirnya jadi juga library stcp\"}",
     STCP_REQ_COMPLETE
    ));
    return 0;
}

// purpose : send message to bot telegram