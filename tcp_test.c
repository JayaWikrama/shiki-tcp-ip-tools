#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include "shiki-tcp-ip-tools.h"

int main(){ 
    char response[1000];
    stcp_https_post("api.telegram.org", 443,
     "bot1007413403:AAHfALG30Bc4U0h_o1mNqUu-51AD105ggWU/sendMessage",
     "Content-Type: application/json", "{\"chat_id\": \"1030198712\", \"text\": \"Akhirnya jadi juga library stcp\"}",
     response, STCP_REQ_CONTENT_ONLY
    );
    printf("%s\n", response);
    return 0;
}

// purpose : send message to bot telegram