#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <thread>
#include <iostream>
#include <sstream>
using namespace std;

#include "func/sha256.cpp"
#include "func/digits.cpp"
#include "func/rsa.cpp"
#include "func/database.cpp"
#include "func/keyExchange.cpp"
#include "func/msg_encr_decr.cpp"
#include "func/aes.cpp"

//#define SEE
#define BORDER 6
/*

using namespace std;

 * компиляция: g++ server.cpp -o server -lgmpxx -lgmp -pthread -lcryptopp -l sqlite3
 * запуск:     ./server 127.0.0.1 8080
 *            адрес сервера /\     /\ порт, на котором работает сервер
 *
 * Проблема - после отключения одного из клиентов, сервер и другой клиент уходят в бесконечный цикл.
 * На работоспособность чата не влияет, но надо исправить

*/

/* -------------------------==[work with messages]==------------------------- */
void msg_1_to_2(int sockfd_1, int sockfd_2)
{
	/* соединение первого пользователя со вторым */
	 struct encrypted
	 {
	 char from_session_id[2048];
	 char to_session_id[2048];
	 //string auth_key_id;
	 char msg_key[2048];
	 char encrypted_data[2048];
	 }data;
	
	while(!feof(stdin))
	{
		recv(sockfd_2, &data, sizeof(data), 0);
		
		getKey_db_s(sockfd_2, data.from_session_id, "USERS");
		string from_auth_key = key_data.auth_key;

		getKey_db_s(sockfd_1, data.to_session_id, "USERS");
		string to_auth_key = key_data.auth_key;
		
		string aes_key = get_aes_key( string(data.msg_key), from_auth_key);
		string aes_iv = get_aes_iv( string(data.msg_key), from_auth_key);
		string decrypted_data = AES256Decode( string(data.encrypted_data), aes_key, aes_iv);
		
		#ifdef SEE
		cout << "got new encrypted data from id "<< string(data.from_session_id).substr(0, BORDER) << "..." << string(data.from_session_id).substr(strlen(data.from_session_id)-BORDER) <<" : " << data.encrypted_data << endl;
		cout << "msg_key: " << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << endl;
		cout << "aes_key: " << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << endl;
		cout << "decrypted data: " << decrypted_data << endl;
		#endif // SEE
		
		cout << data.from_session_id << " : " << decrypted_data;
		
		aes_key = get_aes_key(string(data.msg_key), to_auth_key);
		aes_iv = get_aes_iv(string(data.msg_key), to_auth_key);
		strcpy(data.encrypted_data, AES256Encode(decrypted_data, aes_key, aes_iv).c_str() );
		
		#ifdef SEE
		cout << "encrypted message with new data: " << data.encrypted_data << endl;
		cout << "now send in to sock_id " << sockfd_2 << endl << endl;
		#endif // SEE
		
		send(sockfd_1, &data, sizeof(data), 0);
	}
}

void msg_2_to_1(int sockfd_1,int sockfd_2)
{
	/* соединение второго пользователя с первым */
	struct encrypted{
		char from_session_id[2048];
		char to_session_id[2048];
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	} data;

	
	while(!feof(stdin))
	{
		/* WORK WITH KEY HERE */
		recv(sockfd_1, &data, sizeof(data), 0);
		
		getKey_db_s(sockfd_1, data.from_session_id, "USERS");
		string from_auth_key = key_data.auth_key;
		
		getKey_db_s(sockfd_2, data.to_session_id, "USERS");
		string to_auth_key = key_data.auth_key;
		
		string aes_key = get_aes_key( string(data.msg_key), from_auth_key);
		string aes_iv = get_aes_iv( string(data.msg_key), from_auth_key);
		string decrypted_data = AES256Decode( string(data.encrypted_data), aes_key, aes_iv);
		
		#ifdef SEE
		cout << "got new encrypted data from id "<< string(data.from_session_id).substr(0, BORDER) << "..." << string(data.from_session_id).substr(strlen(data.from_session_id)-BORDER) <<" : " << data.encrypted_data << endl;
		cout << "msg_key: " << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << endl;
		cout << "aes_key: " << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << endl;
		cout << "decrypted data: " << decrypted_data << endl << endl;
		#endif // SEE
		
		cout << data.from_session_id << " : " << decrypted_data;
		
		#ifdef SEE
		cout << "encrypted message with new data: " << data.encrypted_data << endl;
		cout << "now send in to sock_id " << sockfd_2 << endl << endl;
		#endif // SEE
		
		aes_key = get_aes_key( string(data.msg_key), to_auth_key);
		aes_iv = get_aes_iv( string(data.msg_key), to_auth_key);
		strcpy(data.encrypted_data, AES256Encode(decrypted_data, aes_key, aes_iv).c_str() );
		
		send(sockfd_2, &data, sizeof(data), 0);
	}
}

void send_all(int users_sockets[], char *notification_msg)
{
	/* отправка сообщения на все клиенты */
	for (int i = 0; i < 2; i++)
		send(users_sockets[i], notification_msg, 64, 0);
}
/* -------------------------==[end: work with messages]==------------------------- */


/* -------------------------==[work with clients]==------------------------- */
int main(int argc, char **argv){
	
	if (argc != 3) { printf("server: invalid data\n"); exit(1); }
	
	createTable_s("USERS");
	delAll_db("USERS");    // очистка бд

    /* генерируем PublicKey PrivateKey сервера */
	//keyGen("rsa-server-public.key", "rsa-server-private.key")

    char host_ip[16];                   /* ip хоста   */
    strncpy(host_ip, argv[1], 16);
	short host_port = atoi(argv[2]);    /* порт хоста */

    struct sockaddr_in client_addr, host_addr;

    int sockfd = 0;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (inet_pton(AF_INET, host_ip, &host_addr.sin_addr) <= 0) 
		{ perror("address parsing"); return 1; }

    host_addr.sin_port = htons(host_port);
    host_addr.sin_family = AF_INET;
    //host_addr.sin_addr.s_addr = inet_addr(host_addr);
    //memset(&(host_addr.sin_zero), '\0', 8);

    if( bind(sockfd, (struct sockaddr*)&host_addr, sizeof(host_addr)) < 0) 
		{ perror("bind"); return 2; }

    printf("server: running  | server ip (%s) on port %d\n", host_ip, host_port);

    if (listen(sockfd, 2) == -1) 
		{ perror("listening on socket"); return 3; }

    char users_ip[2][16];          /* адреса подключенных клиентов      */
    int  users_sockets[2], i = 0;  /* дескрипторы сокетов клиентов      */
    int new_socket = 0;            /* дескриптор сокета нового клиента  */
    
    //thread requests(request, users_sockets[0], users_sockets[1]); /* поток обрабатывающий запросы */
	//fpipe_2.join();

    while (!feof(stdin))
	{
        socklen_t size = sizeof(struct sockaddr_in);
        new_socket = accept(sockfd, (struct sockaddr*)&client_addr, &size);
		
        if (new_socket < 0) 
			{ perror("new socket"); return 4; }

        printf("server: got new connection | %s | %d | sockfd -> %d\n",
                inet_ntoa(client_addr.sin_addr), host_port, new_socket);

		strncpy(users_ip[i], inet_ntoa(client_addr.sin_addr), 16);  /* адреса подключенных клиентов */
		users_sockets[i] = new_socket;                              /* дескрипторы сокетов клиентов */

        new_session_server(users_sockets[i]);
        i++;

		/* отправка уведомления о подключении */
        char notification_msg[64] = "server: connected";
        send(new_socket, notification_msg, 64, 0);
        memset(notification_msg, '\0', 64);
		
		

        if (i == 2)
        {
            strcpy(notification_msg, "all users online, let's go bowling\n\n");
            printf("%s", notification_msg);
            send_all(users_sockets, notification_msg);
            memset(notification_msg, '\0', 64);
            i = 0;

			/* отправка сообщений */
			thread fpipe_1(msg_1_to_2, users_sockets[0], users_sockets[1]); /* поток, связывающий первого и второго пользователя */
			thread fpipe_2(msg_1_to_2, users_sockets[1], users_sockets[0]); /* поток, связывающий второго и первого пользователя */

            /* приём сообщений */
			thread bpipe_1(msg_2_to_1, users_sockets[0], users_sockets[1]); /* поток, связывающий первого и второго пользователя */
			thread bpipe_2(msg_2_to_1, users_sockets[1], users_sockets[0]); /* поток, связывающий второго и первого пользователя */

            fpipe_1.join();
            bpipe_1.join();

            fpipe_2.join();
            bpipe_2.join();
        }
        //break;

    }
    close (users_sockets[0]);
	close (users_sockets[1]);

    return 0;
}
