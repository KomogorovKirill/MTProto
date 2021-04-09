#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

void fatal(char *err_str){
    printf("%s", err_str);
    exit(1);
}

int main(int argc, char **argv){

    char *host_ip = "127.0.0.1"; 
    short port = 8080;
    struct sockaddr_in client_addr, host_addr;

    int sockfd = 0, new_socket = 0;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (inet_pton(AF_INET, host_ip, &host_addr.sin_addr) <= 0) {
		perror("address parsing");
		return 2;
	}

    host_addr.sin_port = htons(port);
    host_addr.sin_family = AF_INET;
    //host_addr.sin_addr.s_addr = inet_addr(host_addr);
    //memset(&(host_addr.sin_zero), '\0', 8);

    if( bind(sockfd, (struct sockaddr*)&host_addr, sizeof(host_addr)) < 0){
        perror("bind");
    }

    if (listen(sockfd, 1) == -1)  
        perror("listening on socket");

    int recv_len = 0;
    char buffer[1024] = "connected";
    
    
    while (1){
        socklen_t size = sizeof(struct sockaddr_in);
        new_socket = accept(sockfd, (struct sockaddr*)&client_addr, &size);
        if (new_socket < 0){
            perror("new socket");
            //return 0;
        }
        printf("new_socket: %d\n",
                new_socket);
        
        printf("server: got new connection %s : %d\n",
                inet_ntoa(client_addr.sin_addr), port);


        send(new_socket, "Connected!\n", 10, 0);
        printf("send: %d\n",
                send);

        recv_len = recv(new_socket, buffer, 1024, 0);
        
        while (recv_len > 0){
            printf("%s", buffer);
            recv_len = recv(new_socket, buffer, 1024, 0);
        }
    }
        close (new_socket);
    
      
    return 0;
}
