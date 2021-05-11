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
#include <iomanip>
using namespace std;

#include "func/sha256.cpp"
#include "func/digits.cpp"
#include "func/rsa.cpp"
#include "func/aes.cpp"
#include "func/database.cpp"
#include "func/keyExchange.cpp"
#include "func/msg_encr_decr.cpp"



/* компиляция: g++ client.cpp -o client -lgmpxx -lgmp -pthread -lcryptopp -l sqlite3
 * запуск:     ./client 127.0.0.1 8080
 *            адрес сервера /\     /\ порт, на котором работает сервер
 *
 * Проблема - после отключения одного из клиентов, сервер и другой клиент уходят в бесконечный цикл.
 * На работоспособность чата не влияет, но надо исправить
 
 */



/* -------------------------==[work with messages]==------------------------- */
void form_to_be_encrypted()
{
	
}

void send_msg(int sockfd){
	
	struct encrypted{
		char from_session_id[2048];
		char to_session_id[2048];
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	} data;
	
	char msg_out[1024];
	string to_be_encrypted;
	
	getId_db("USER");
	string session_id = key_data.id;
	
	getKey_db_c(session_id, "USER");
	string from_auth_key = key_data.auth_key;

	strncpy(data.from_session_id, session_id.c_str(), 64);	
	
	while(!feof(stdin))
	{
		fgets(msg_out, 1024, stdin);
		// ENCRYPTION 
		to_be_encrypted = string(msg_out); // формирование to be encrypted block
		
		strncpy(data.msg_key, get_msg_key(to_be_encrypted, from_auth_key).c_str(), 2048);
		
		string aes_key = get_aes_key(string(data.msg_key), from_auth_key);
		string aes_iv = get_aes_iv(string(data.msg_key), from_auth_key);
		
		strncpy(data.encrypted_data, AES256Encode(to_be_encrypted, aes_key, aes_iv).c_str(), 2048);
		
		#ifdef SEE
		cout << "--------------------------------------+" << endl;
		cout << "Field "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) start encrypt data" << endl;
		cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | " << "enc_msg: " << data.encrypted_data << endl;
		cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << endl;
		cout << "aes_iv " << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl;
		cout << "--------------------------------------+" << endl << endl;
		#endif // SEE
		
		send(sockfd, &data, sizeof(data), 0);
	}
	//close (sockfd);
	//exit(1);
}

void get_msg(int sockfd){
	
	struct encrypted{
		char from_session_id[2048];
		char to_session_id[2048];
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	} data;

	
	char msg_in[1024];
	int recv_len;
	
	string to_be_encrypted;
	
	getId_db("USER");
	string session_id = key_data.id;
	
	getKey_db_c(string(session_id), "USER");
	string auth_key = key_data.auth_key;
	
	
	while(1)
	{
		recv_len = recv(sockfd, &data, sizeof(data), 0);
		// DECRYPTION
		
		string aes_key = get_aes_key(string(data.msg_key), auth_key);
		string aes_iv = get_aes_iv(string(data.msg_key), auth_key);
		string decrypted_data = AES256Decode(data.encrypted_data, aes_key, aes_iv);
		
		#ifdef SEE
		cout << "--------------------------------------+" << endl;
		cout << "Field "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) got new data from server, start decryptiom" << endl;
		cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | " << "enc_msg: " << data.encrypted_data << endl;
		cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << endl;
		cout << "aes_iv " << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl;
		cout << "--------------------------------------+" << endl;
		#endif // SEE
		
		cout << "> " << decrypted_data;
		//printf("> %s", msg_in);
	}
	//close (sockfd);
}
/* -------------------------==[end: work with messages]==------------------------- */


/* -------------------------==[work with clients]==------------------------- */
int main(int argc, char **argv){
	
	if (argc != 3) { printf("client: invalid data\n"); exit(1); }
	cout << "MTproto: cloud chat (server-client encryption)" << endl << endl;
	
	createTable_c("USER");
	delAll_db("USER");    // очистка бд
	
	// генерируем PublicKey PrivateKey клиента
	//keyGen("rsa-client-public.key", "rsa-client-private.key")
	
	// данные для подключения клиентов
	char host_ip[16];                   // ip хоста
	strncpy(host_ip, argv[1], 16);
	short host_port = atoi(argv[2]);    // порт хоста
	
	struct sockaddr_in client_addr;
	
	int sockfd = 0;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (inet_pton(AF_INET, host_ip, &client_addr.sin_addr) <= 0) 
		{ perror("address parsing"); return 2; }

	// заполнение структуры данными клиента
    client_addr.sin_port = htons(host_port);
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr(host_ip);
    //memset(&(host_addr.sin_zero), '\0', 8);

    if( connect(sockfd, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0)
		{ perror("connect"); return 3; }
	
	new_session_client(sockfd);
	getId_db("USER");
	string session_id = key_data.id;
	
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

	delUser_db_c(session_id, "USER");
    close (sockfd);
	
	

    return 0;
}
