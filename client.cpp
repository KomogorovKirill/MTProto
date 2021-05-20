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



#include "digits.cpp"
#include "sha256.cpp"
#include "rsa.cpp"
#include "aes.cpp"
#include "database.cpp"
#include "keyExchange.cpp"
#include "msg_encr_decr.cpp" 
//#include "pretty_output.cpp"

/* компиляция: g++ client.cpp -o client -lgmpxx -lgmp -pthread -lcryptopp -l sqlite3
 * запуск:     ./client 127.0.0.1 8080
 *            адрес сервера /\     /\ порт, на котором работает сервер
 *
 * Проблема - после отключения одного из клиентов, сервер и другой клиент уходят в бесконечный цикл.
 * На работоспособность чата не влияет, но надо исправить
 
 */

/* -------------------------==[work with messages]==------------------------- */

void sendMsg(int sockfd){
	
	/*
	typedef struct {
		uint8_T salt [] ;
		uint8_t sess_id ;
		uint16_t len ;
		uint8_t data ;
	}; // без выравнивание
	*/
	struct package
	{
		char sender_session_id[2048];
		char recipient_session_id[2048];
		int msg_len;
		char sender_username[32];
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	}data;
	
	char msg_out[1024];
	int send_value = 0;
	
	/* get senders's sesion id */
	db_get_id("USER");
	string session_id = db_user_data.session_id;
	
	/* get sender's auth_key */
	db_getKey_client(session_id, "USER");
	string sender_auth_key = db_user_data.auth_key;

	strncpy(data.sender_session_id, session_id.c_str(), 64);	
	
	while(!feof(stdin))
	{
		fgets(msg_out, 512, stdin);

		/* формирование to be encrypted block */
		string to_be_encrypted = getEncryptedBlock(session_id, string(msg_out));
		data.msg_len = string(msg_out).length() - 1;

		strncpy(data.msg_key, get_msg_key(to_be_encrypted, sender_auth_key).c_str(), 2048);
		
		string aes_key = get_aes_key(string(data.msg_key), sender_auth_key);
		string aes_iv = get_aes_iv(string(data.msg_key), sender_auth_key);
		
		strncpy(data.encrypted_data, AES256Encode(to_be_encrypted, aes_key, aes_iv).c_str(), 2048);
		strncpy(data.sender_username, username.c_str(), 32);
		
		//#ifdef SEE
		//	prettyCout_3();
		//#endif // SEE
		
		send(sockfd, &data, sizeof(data), 0);
	}
	close(sockfd);
}

void getMsg(int sockfd){
	
	struct package
	{
		char sender_session_id[2048];
		char recipient_session_id[2048];
		int msg_len;
		char sender_username[32];
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	}data;
	
	int recv_len = 0;
	
	/* get senders's sesion id */
	db_get_id("USER");
	string session_id = db_user_data.session_id;
	
	/* get sender's auth_key */
	db_getKey_client(string(session_id), "USER");
	string auth_key = db_user_data.auth_key;
	
	while( recv_len != -1 )
	{
		recv_len = recv(sockfd, &data, sizeof(data), 0);
		
		string aes_key = get_aes_key(string(data.msg_key), auth_key);
		string aes_iv = get_aes_iv(string(data.msg_key), auth_key);
		string decrypted_data = AES256Decode(data.encrypted_data, aes_key, aes_iv);
		//cout << decrypted_data << endl;
		
		//#ifdef SEE
		//	prettyCout_4();
		//#endif // SEE
		
		cout << data.sender_username << "> " << decrypted_data.substr(38, data.msg_len) + "\n";
	}
}
/* -------------------------==[end: work with messages]==------------------------- */


/* -------------------------==[work with clients]==------------------------- */
int main(int argc, char **argv){
	
	if (argc != 3) { printf("client: invalid data\n"); exit(1); }
	cout << "MTproto: cloud chat (server-client encryption)" << endl << endl;
	
	db_createTable_client("USER");
	db_delAll("USER");  // очистка бд
	
	// генерируем PublicKey PrivateKey клиента
	RSAkeyGen("rsa-client-public.key", "rsa-client-private.key");
	
	// данные для подключения к серверу
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
	
	getNewSession_client(sockfd);
	db_get_id("USER");
	string session_id = db_user_data.session_id;

	thread msg_receiving_stream(getMsg, sockfd);     // поток для обработки входящих сообщений
	thread msg_sending_stream(sendMsg, sockfd);    // поток для обработки исходящих сообщений

	msg_receiving_stream.join();
	msg_sending_stream.join();

	db_delUser_client(session_id, "USER");
    close(sockfd);

    return 0;
}
