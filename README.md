General Information
    lib info    : SHIKI_LIB_GROUP - TCP_IP
    ver         : 1.01.19.10.03.18
    author      : Jaya Wikrama, S.T.
    e-mail      : jayawikrama89@gmail.com
    Copyright (c) 2019 HANA,. Jaya Wikrama

Tested on Ubuntu Linux, Raspbian Stretch, ESP32 ARDUINO



>>>>>> example code for server :

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "shiki-tcp-ip-tools.h"

int main() 
{ 
    struct stcp_sock_data socket_f = stcp_server_init("192.168.43.174", 8080, WITHOUT_RETRY, STCP_DEBUG_ON);
	char my_text[80];	
	int ret_status = 0;
    while(ret_status >= 0){
		memset(my_text, 0x00, 10*sizeof(char));
        stcp_recv_data(socket_f, my_text, 10);
        stcp_send_data(socket_f, "TES SER", strlen("TES SER"));
        sleep(1);
    }
	stcp_close(socket_f);
    return 0;
}



>>>>>> example code for client :

#include <stdio.h>
#include <string.h>
#include "shiki-tcp-ip-tools.h"

int main() 
{ 
    struct stcp_sock_data socket_f = stcp_client_init("192.168.43.174", 8080, WITHOUT_RETRY, STCP_DEBUG_ON);
    char my_text[80];
	int ret_status = 0;
    while(ret_status >= 0){
		memset(my_text, 0x00, 10*sizeof(char));
        stcp_send_data(socket_f, "TES CLI\n", strlen("TES CLI\n"));
        stcp_recv_data(socket_f, my_text, 10);
		printf("%s\n", my_text);
    }
	stcp_close(socket_f);
    return 0;
}


>>>>>> example code for ESP32 ARDUINO (as server) :

#include <WiFi.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern "C"{
  #include "shiki-tcp-ip-tools.h"
}

#define ssid "your_wifi_ssid"
#define password "your_wifi_password"

#define MAX_LEN_BUFF 100

void setup() {
  char cmd_send_to_uart[MAX_LEN_BUFF];
  pinMode(2, OUTPUT);
  Serial.begin(115200);

  memset(cmd_send_to_uart, 0x00, MAX_LEN_BUFF*sizeof(char));
  sprintf(cmd_send_to_uart, "try to connecting to :\n%s\n", ssid);
  Serial.println(cmd_send_to_uart);

  WiFi.begin(ssid, password);
 
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.print(".");
  }
  Serial.print("\nwifi connected successfully\nYour Ip: ");
  Serial.println(WiFi.localIP());
}
 
void loop() {
  struct stcp_sock_data socket_f = stcp_server_init("192.168.43.174", 8080, WITHOUT_RETRY, STCP_DEBUG_ON);
  char my_text[80];
  int ret_status = 0;
  while(ret_status >= 0){
        memset(my_text, 0x00, 10*sizeof(char));
        ret_status = stcp_recv_data(socket_f, my_text, 10);
        ret_status = stcp_send_data(socket_f, "TESSER\n", strlen("TESSER\n"));
        Serial.printf("Data In : ");
        Serial.println(my_text);
        sleep(1);
  }
  stcp_close(socket_f);
  sleep(1);  
}


note :
1. change IP addres in example with your TCP Server IP
2. if you use this library on ESP32 ARDUINO project (with <Wifi.h>), move "#include <arpa/inet.h>" on shiki-tcp-ip-tools.c