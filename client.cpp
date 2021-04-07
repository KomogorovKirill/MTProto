#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <thread>
#include <iostream>
using namespace std;

/* компиляция: g++ client.cpp -o client -pthread
 * запуск:     ./client 127.0.0.1 8080
 *            адрес сервера /\     /\ порт, на котором работает сервер
 * 
 * Проблема - после отключения одного из клиентов, сервер и другой клиент уходят в бесконечный цикл.
 * На работоспособность чата не влияет, но надо исправить
*/

void get_msg(int sockfd){

    char msg_out[1024];
    while(!feof(stdin))
    {
        fgets(msg_out, 1024, stdin);
        // ENCRIPTION HERE
        send(sockfd, msg_out, 1024, 0);
    }
    exit(1);
}

void send_msg(int sockfd){

    char msg_in[1024];
    int recv_len;
    while(1)
    {
        recv_len = recv(sockfd, msg_in, 1024, 0);
        // DECRIPTION HERE
        printf("> %s", msg_in);
    }
}


int main(int argc, char **argv){
    
    if (argc != 3){
        printf("client: invalid data\n");
        exit(1);
    }
    
    // данные для подключения клиентов
    char host_ip[16];                   // ip хоста
    strncpy(host_ip, argv[1], 16);
    short host_port = atoi(argv[2]);    // порт хоста
    
    
    struct sockaddr_in client_addr;

    int sockfd = 0;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (inet_pton(AF_INET, host_ip, &client_addr.sin_addr) <= 0) {
		perror("address parsing");
		return 2;
	}

	// заполнение структуры данными клиента
    client_addr.sin_port = htons(host_port);
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr(host_ip);
    //memset(&(host_addr.sin_zero), '\0', 8);

    if( connect(sockfd, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0){
        perror("connect");
        return 3;
    }

    // приём уведомления от сервера о подключении к нему
    char notification_msg[64];
    recv(sockfd, notification_msg, 64, 0);
    printf("%s\n",notification_msg);
    memset(notification_msg, '\0', 64);
    
    // приём уведомления от сервера о подключении второго клиента
    recv(sockfd, notification_msg, 64, 0);
    printf("%s\n",notification_msg);
    memset(notification_msg, '\0', 64);
    
    thread getting_thread(get_msg, sockfd);     // поток для обработки входящих сообщений
    thread sending_thread(send_msg, sockfd);    // поток для обработки исходящих сообщений

    sending_thread.join();
    getting_thread.join();

    close (sockfd);


    return 0;
}

