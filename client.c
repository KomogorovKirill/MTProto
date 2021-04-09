#include <unistd.h>
#include <stdio.h> 
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

int main(int argc, char **argv){
    //char remote_ip[] = "0.0.0.0";
    char host_ip[] = "127.0.0.1";
    //char host_ip[] = argv[1];
    //short host_port[] = atoi(argv[2]);
    //remote_ip[] = argv[2];
    //
    short host_port = 8080;
    
    struct sockaddr_in client_addr;
    
    // CREATE SOCKET
    int sockfd = 0;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sockfd < 0){
        perror("socket creation");
        return 1;
    }
    
    // FILL SOCADDR_IN
    if (inet_pton(AF_INET, host_ip, &client_addr.sin_addr) <= 0){
        perror("adress parsing");
        return 2;
    }
    client_addr.sin_port = htons(host_port);
    client_addr.sin_family = AF_INET;
    
    
    // CONNECT
    if (connect(sockfd, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0 ){
        perror("connect");
        return 3;
    }
    
    char msg_out[1024];
    char msg_in[1024];
    
    //recv_len = recv(sockfd, msg_in, 1024, 0);
    //printf("from %s: %s", host_ip, msg_in);
    
    while (1) {
        
        printf("you: ");
        send(sockfd, msg_out, 1024, 0);
    }
    
    return 0;
    //getenv("USER");
}
