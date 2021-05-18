#include "func/include.cpp"
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


void sendMsg(int *recipient_socket, int sender_socket)
{
	/* соединение первого пользователя со вторым */
	struct package
	{
		char sender_session_id[2048];
		char recipient_session_id[2048];
		int msg_len;
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	}data;
	
	int recv_len = 0, send_value = 0;
	string db_decryption_aes_key = "qwertyuiopasdfghjklzxcvbnmqwerty";
	string db_decryption_aes_iv = "0123456789123456";
	
	while( recv_len != -1 || send_value != -1 )
	{
		recv_len = recv(sender_socket, &data, sizeof(data), 0);
		
		db_getKey_server(sender_socket, "USERS");
		string sender_auth_key = db_user_data.auth_key;
		sender_auth_key = AES256Decode_db(sender_auth_key, db_decryption_aes_key,  db_decryption_aes_iv);
		
		string aes_key = get_aes_key( string(data.msg_key), sender_auth_key);
		string aes_iv = get_aes_iv( string(data.msg_key), sender_auth_key);
		string decrypted_data = AES256Decode( string(data.encrypted_data), aes_key, aes_iv);
		
		sender_auth_key = "0000";
		
		//#ifdef SEE
		//	prettyCout_1();
		//#endif // SEE
		
		cout << data.sender_session_id << " : " << decrypted_data.substr(38, data.msg_len) + "\n";
		//cout << data.sender_session_id << " : " << decrypted_data;
		
		for (int i = 0; i < 10; i++)
		{
			if (sender_socket != recipient_socket[i] && recipient_socket[i] != 0)
			{
				db_getKey_server(recipient_socket[i], "USERS");
				string recipient_auth_key = db_user_data.auth_key;
				recipient_auth_key = AES256Decode_db(recipient_auth_key, db_decryption_aes_key,  db_decryption_aes_iv);
		
				aes_key = get_aes_key(string(data.msg_key), recipient_auth_key);
				aes_iv = get_aes_iv(string(data.msg_key), recipient_auth_key);
				strcpy(data.encrypted_data, AES256Encode(decrypted_data, aes_key, aes_iv).c_str() );
		
				recipient_auth_key = "0000";
		
				//#ifdef SEE
				//	prettyCout_2();
				//#endif // SEE
		
				send_value = send(recipient_socket[i], &data, sizeof(data), 0);
			}
		}
	}
}
/* -------------------------==[end: work with messages]==------------------------- */


/* -------------------------==[work with clients]==------------------------- */
int main(int argc, char **argv){
	
	if (argc != 3) { printf("server: invalid data\n"); exit(1); }
	cout << "MTproto: cloud chat (server-client encryption)" << endl << endl;
	
	db_createTable_server("USERS");
	db_delAll("USERS");    // очистка бд

    /* генерируем PublicKey PrivateKey сервера */
	//RSAkeyGen("rsa-server-public.key", "rsa-server-private.key")

    char host_ip[16];                   /* ip хоста   */
    strncpy(host_ip, argv[1], 16);
	short host_port = atoi(argv[2]);    /* порт хоста */
	int sockfd = 0;

    struct sockaddr_in client_addr, host_addr;
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

    int  sockets[10] = {0}, i = 0;        /* дескрипторы сокетов клиентов      */
    int  new_socket = 0;           		  /* дескриптор сокета нового клиента  */

    while (!feof(stdin))
	{
        socklen_t size = sizeof(struct sockaddr_in);
        new_socket = accept(sockfd, (struct sockaddr*)&client_addr, &size);
		
        if (new_socket < 0) 
			{ perror("new socket"); return 4; }
		
		printf("server: got new connection | %s:8080 | sockfd -> %d\n", 
			   inet_ntoa(client_addr.sin_addr), new_socket);
		
		if (i+1 > 10) 
			{ cout << "group full of users" << endl; continue; }
		
		sockets[i] = new_socket;
		getNewSession_server(sockets[i++]);
		
		thread data_stream(sendMsg, sockets, new_socket);
		data_stream.detach();

    }
    for (int i = 0; i < 10; i++)
    	close(sockets[i]);
	

    return 0;
}
