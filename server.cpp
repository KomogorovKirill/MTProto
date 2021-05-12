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

/*
void listen ()
{
	struct encrypted
	{
		char sender_session_id[2048];
		char recipient_session_id[2048];
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	}data;
	
	recv(sockfd_2, &data, sizeof(data), 0);
}
*/

/* -------------------------==[work with messages]==------------------------- */
/*
string get_msg_from_to_be_encrypted(string to_be_encrypted)
{
	int msg_len = stoi(to_be_encrypted.substr(32, 2));
	cout << "msglen" << msg_len << endl;
	string msg = to_be_encrypted.substr(34, msg_len);
	return msg;
}
*/

void sendMsg(int recipient_socket, int sender_socket)
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
	 
	string db_decryption_aes_key = "qwertyuiopasdfghjklzxcvbnmqwerty";
	string db_decryption_aes_iv = "0123456789123456";
	
	while(!feof(stdin))
	{
		recv(sender_socket, &data, sizeof(data), 0);
		
		db_getKey_server(sender_socket, data.sender_session_id, "USERS");
		string sender_auth_key = key_data.auth_key;
		sender_auth_key = AES256Decode_db(sender_auth_key, db_decryption_aes_key,  db_decryption_aes_iv);
		
		string aes_key = get_aes_key( string(data.msg_key), sender_auth_key);
		string aes_iv = get_aes_iv( string(data.msg_key), sender_auth_key);
		string decrypted_data = AES256Decode( string(data.encrypted_data), aes_key, aes_iv);
		
		sender_auth_key = "0000";
		
		#ifdef SEE
		string e_data = string(data.encrypted_data);
		cout << "--------------------------------------+" << endl;
		cout << "Field "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) decrypting encrypted information" << endl;
		if (e_data.length() > 10){
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
			cout << "enc_msg: " << e_data.substr(0, BORDER) << "..." << e_data.substr(e_data.length()-BORDER) << endl;}
		else
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | " << "enc_msg: " << data.encrypted_data << endl;
		cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << "from_id " << data.sender_session_id << endl;
		cout << "aes_iv "  << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl << endl;
		#endif // SEE
		
		cout << data.sender_session_id << " : " << decrypted_data.substr(39, data.msg_len) + "\n";
		//cout << data.sender_session_id << " : " << decrypted_data;
		
		db_getKey_server(recipient_socket, data.recipient_session_id, "USERS");
		string recipient_auth_key = key_data.auth_key;
		recipient_auth_key = AES256Decode_db(recipient_auth_key, db_decryption_aes_key,  db_decryption_aes_iv);
		
		aes_key = get_aes_key(string(data.msg_key), recipient_auth_key);
		aes_iv = get_aes_iv(string(data.msg_key), recipient_auth_key);
		strcpy(data.encrypted_data, AES256Encode(decrypted_data, aes_key, aes_iv).c_str() );
		
		recipient_auth_key = "0000";
		
		#ifdef SEE
		e_data = string(data.encrypted_data);
		cout << "\nField "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) encrypting information with new data" << endl;
		if (e_data.length() > 10){
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
			cout << "enc_msg: " << e_data.substr(0, BORDER) << "..." << e_data.substr(e_data.length()-BORDER) << endl;}
		else
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | " << "enc_msg: " << data.encrypted_data << endl;
		cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << endl;
		cout << "aes_iv "  << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl;
		cout << "--------------------------------------+" << endl << endl;
		#endif // SEE
		
		send(recipient_socket, &data, sizeof(data), 0);
	}
}

void getMsg(int sender_socket,int recipient_socket)
{
	/* соединение второго пользователя с первым */
	struct package
	{
		char sender_session_id[2048];
		char recipient_session_id[2048];
		int msg_len;
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	}data;

	string db_decryption_aes_key = "qwertyuiopasdfghjklzxcvbnmqwerty";
	string db_decryption_aes_iv = "0123456789123456";
	
	while(!feof(stdin))
	{
		/* WORK WITH KEY HERE */
		recv(sender_socket, &data, sizeof(data), 0);
		
		db_getKey_server(sender_socket, data.sender_session_id, "USERS");
		string sender_auth_key = key_data.auth_key;
		sender_auth_key = AES256Decode_db(sender_auth_key, db_decryption_aes_key,  db_decryption_aes_iv);
		
		string aes_key = get_aes_key( string(data.msg_key), sender_auth_key);
		string aes_iv = get_aes_iv( string(data.msg_key), sender_auth_key);
		string decrypted_data = AES256Decode( string(data.encrypted_data), aes_key, aes_iv);
		
		sender_auth_key = "0000";
		
		#ifdef SEE
		string e_data = string(data.encrypted_data);
		cout << "--------------------------------------+" << endl;
		cout << "Field "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) decrypting encrypted information" << endl;
		if (e_data.length() > 10){
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
			cout << "enc_msg: " << e_data.substr(0, BORDER) << "..." << e_data.substr(e_data.length()-BORDER) << endl;}
		else
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | " << "enc_msg: " << data.encrypted_data << endl;
		cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << "from_id " << data.sender_session_id << endl;
		cout << "aes_iv "  << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl << endl;
		#endif // SEE
		
		cout << data.sender_session_id << " : " << decrypted_data.substr(39, data.msg_len) + "\n";
		//cout << data.sender_session_id << " : " << decrypted_data;
		
		db_getKey_server(recipient_socket, data.recipient_session_id, "USERS");
		string recipient_auth_key = key_data.auth_key;
		recipient_auth_key = AES256Decode_db(recipient_auth_key, db_decryption_aes_key,  db_decryption_aes_iv);
		
		aes_key = get_aes_key(string(data.msg_key), recipient_auth_key);
		aes_iv = get_aes_iv(string(data.msg_key), recipient_auth_key);
		strcpy(data.encrypted_data, AES256Encode(decrypted_data, aes_key, aes_iv).c_str() );
		
		recipient_auth_key = "0000";
		
		#ifdef SEE
		e_data = string(data.encrypted_data);
		cout << "\nField "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) encrypting information with new data" << endl;
		if (e_data.length() > 10){
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
			cout << "enc_msg: " << e_data.substr(0, BORDER) << "..." << e_data.substr(e_data.length()-BORDER) << endl;}
		else
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | " << "enc_msg: " << data.encrypted_data << endl;
		cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << endl;
		cout << "aes_iv "  << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl;
		cout << "--------------------------------------+" << endl << endl;
		#endif // SEE
		
		send(recipient_socket, &data, sizeof(data), 0);
	}
}

void send_all(int sockets[], string notification_msg)
{
	/* отправка сообщения на все клиенты */
	for (int i = 0; i < 2; i++)
		send(sockets[i], (notification_msg).c_str(), 64, 0);
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

    int  sockets[2], i = 0;        /* дескрипторы сокетов клиентов      */
    int  new_socket = 0;           /* дескриптор сокета нового клиента  */

    while (!feof(stdin))
	{
        socklen_t size = sizeof(struct sockaddr_in);
        new_socket = accept(sockfd, (struct sockaddr*)&client_addr, &size);
		
        if (new_socket < 0) 
			{ perror("new socket"); return 4; }
			
        printf("server: got new connection | %s | %d | sockfd -> %d\n", 
			   inet_ntoa(client_addr.sin_addr), host_port, new_socket);

		sockets[i] = new_socket;
		getNewSession_server(sockets[i]);
        i++;

        string notification_msg = "server: successful connecion, waiting for the second user";
        send(new_socket, (notification_msg).c_str(), 64, 0);

        if (i == 2)
        {
			notification_msg = "all users online, let's go bowling\n";
            cout << notification_msg;
            send_all(sockets, notification_msg);
            i = 0;
			
			/* отправка сообщений */
			thread msg_sending_stream_1(sendMsg, sockets[0], sockets[1]); /* поток, связывающий первого и второго пользователя */
			thread msg_sending_stream_2(sendMsg, sockets[1], sockets[0]); /* поток, связывающий второго и первого пользователя */

            /* приём сообщений */
			thread msg_receiving_stream_1(getMsg, sockets[0], sockets[1]);  /* поток, связывающий первого и второго пользователя */
			thread msg_receiving_stream_2(getMsg, sockets[1], sockets[0]);  /* поток, связывающий второго и первого пользователя */
			
			msg_sending_stream_1.join();
			msg_receiving_stream_1.join();

			msg_sending_stream_2.join();
			msg_receiving_stream_2.join();
        }
        //break;
    }
    close (sockets[0]);
	close (sockets[1]);

    return 0;
}
