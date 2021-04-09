#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <thread>
#include <cmath>
#include <iostream>
using namespace std;

/* компиляция: g++ server.cpp -o server -pthread
 * запуск:     ./server 127.0.0.1 8080
 *            адрес сервера /\     /\ порт, на котором работает сервер
 * 
 * Проблема - после отключения одного из клиентов, сервер и другой клиент уходят в бесконечный цикл.
 * На работоспособность чата не влияет, но надо исправить
*/

// диффи-хелман генерация ключей 
// id пользователей

void msg_1_to_2(int sockfd_1, int sockfd_2){
    // соединение первого пользователя со вторым
    char msg[1024];
    while(!feof(stdin))
    {
        // WORK WITH KEY HERE
        recv(sockfd_2, msg, 1024, 0);
        printf("%d : %s", sockfd_2, msg);
        send(sockfd_1, msg, 1024, 0);
    }
}

void msg_2_to_1(int sockfd_1,int sockfd_2){
    // соединение второго пользователя с первым
    char msg[1024];
    while(!feof(stdin))
    {
        // WORK WITH KEY HERE
        recv(sockfd_1, msg, 1024, 0);
        printf("%d : %s", sockfd_1, msg);
        send(sockfd_2, msg, 1024, 0);
    }
}

void send_all(int users_sockets[], char *notification_msg){
    // отправка сообщения на все клиенты
    for (int i = 0; i < 2; i++)
        send(users_sockets[i], notification_msg, 64, 0);
}


//===========================
short auth_key_init(int sockfd){
    printf("starting auth key initialisation\n");
    
    FILE *auth_key_file = fopen("auth_key_s", "w");
    
    if (auth_key_file == NULL)
    {
        perror("auth key initialisation");
        exit(1);
    }
    
    
    // ...
    
    
    fprintf(auth_key_file, "%s", "auth_key");
    printf("auth key gen: successfully\n");
    
    return 0;
    
}

bool diffie_hellman(int sockfd){
    // p = 5, g = 13 - random open взаимнопростые 
    // a - secret random
    // A = g^a mop p
    // send A to client
    // B from client: B^a mod p = auth_key
    // начало общения клиента и сервера - генерация auth_key, если нет, а сравнение если есть
    // генерация g p a и передача g p в клиент
    // вычисление auth_key
    //
    
    FILE *auth_key_file = fopen("auth_key_s", "r");
    if (auth_key_file == NULL)
    {
        perror("auth key");
        //auth_key_init(sockfd );
        exit(1);
    }
    
    char auth_key_client[1024];
    char auth_key_server[1024];
    fscanf(auth_key_file, "%s", auth_key_server);
     
    recv(sockfd, auth_key_client, 1024, 0);
    
    if (strcmp(auth_key_server, auth_key_client))
    {  
        printf("user autorisation: failed\n");
        //send(sockfd, "fail", 1024, 0);
        close(sockfd);
        return 1;
    }
    
    send(sockfd, "ok", 1024, 0);
    printf("user autorisation: successfully\n");
    return 0;
}
//===========================

int main(int argc, char **argv){

    if (argc != 3)
    {
        printf("server: invalid data\n");
        exit(1);
    }
    
    char host_ip[16];                   // ip хоста
    strncpy(host_ip, argv[1], 16);      
    short host_port = atoi(argv[2]);    // порт хоста

    struct sockaddr_in client_addr, host_addr;

    int sockfd = 0;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (inet_pton(AF_INET, host_ip, &host_addr.sin_addr) <= 0) 
    {
		perror("address parsing");
		return 1;
	}
	
    host_addr.sin_port = htons(host_port);
    host_addr.sin_family = AF_INET;
    //host_addr.sin_addr.s_addr = inet_addr(host_addr);
    //memset(&(host_addr.sin_zero), '\0', 8);

    if( bind(sockfd, (struct sockaddr*)&host_addr, sizeof(host_addr)) < 0)
    {
        perror("bind");
        return 2;
    }

    printf("server: running  | server ip (%s) on port %d\n",
                                host_ip, host_port);

    if (listen(sockfd, 2) == -1)
    {
        perror("listening on socket");
        return 3;
    }

    
    char users_ip[2][16];       // адреса подключенных клиентов
    int  users_sockets[2], i = 0;  // дескрипторы сокетов клиентов
    int new_socket = 0;         // дескриптор сокета нового клиента 

    while (!feof(stdin)){
        
        socklen_t size = sizeof(struct sockaddr_in);
        new_socket = accept(sockfd, (struct sockaddr*)&client_addr, &size);
        if (new_socket < 0)
        {
            perror("new socket");
            return 4;
        }

        
        printf("server: got new connection | %s | %d | sockfd -> %d\n",
                inet_ntoa(client_addr.sin_addr), host_port, new_socket);
        
        
        strncpy(users_ip[i], inet_ntoa(client_addr.sin_addr), 16);  // адреса подключенных клиентов
        users_sockets[i] = new_socket;                            // дескрипторы сокетов клиентов
        diffie_hellman(users_sockets[i++]);
        
        // отправка уведомления о подключении
        char notification_msg[64] = "server: connected";
        send(new_socket, notification_msg, 64, 0);
        memset(notification_msg, '\0', 64);
        
        if (i == 2) 
        {
            strcpy(notification_msg, "all users online\n");
            printf("%s", notification_msg);
            send_all(users_sockets, notification_msg);
            memset(notification_msg, '\0', 64);
            i = 0;
            
            // отправка сообщений
            thread fpipe_1(msg_1_to_2, users_sockets[0], users_sockets[1]); // поток, связывающий первого и второго пользователя
            thread fpipe_2(msg_1_to_2, users_sockets[1], users_sockets[0]); // поток, связывающий второго и первого пользователя
            
            // приём сообщений
            thread bpipe_1(msg_2_to_1, users_sockets[0], users_sockets[1]); // поток, связывающий первого и второго пользователя
            thread bpipe_2(msg_2_to_1, users_sockets[1], users_sockets[0]); // поток, связывающий второго и первого пользователя
                
            fpipe_1.join();
            bpipe_1.join();
            
            fpipe_2.join();
            bpipe_2.join();
        }
      /*else
        {
            strcpy(notification_msg, "1 of 2 users online, please wait\n");
            printf("%s", notification_msg);
            send_all(users_sockets, notification_msg);
            memset(notification_msg, '\0', 64);
        }*/
        
        //recv_len = recv(new_socket, msg_in,1024, 0);    
    }
        close (new_socket);


    return 0;
}
