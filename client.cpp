#include "func/include.cpp"

/* компиляция: g++ client.cpp -o client -lgmpxx -lgmp -pthread -lcryptopp -l sqlite3
 * запуск:     ./client 127.0.0.1 8080
 *            адрес сервера /\     /\ порт, на котором работает сервер
 *
 * Проблема - после отключения одного из клиентов, сервер и другой клиент уходят в бесконечный цикл.
 * На работоспособность чата не влияет, но надо исправить
 
 */



/* -------------------------==[work with messages]==------------------------- */
string getEncryptedBlock(string session_id, string msg)
{
	static char salt[64];
	while (1)
	{
		getDigit(salt, 64, 0, 10);
		if (!strcmp("0", salt)) { memset(salt, '\0', 64); continue;}
		else break;
	}
	
// 	string payload = to_string( msg.length() ) + msg;
	string payload = msg;
	string to_be_encrypted = salt + session_id + payload;
	
	if (to_be_encrypted.length() < 1024)
	{
		char * padding = new char [1024 - to_be_encrypted.length() + 1];
		memset(padding, '0', 1024 - to_be_encrypted.length() + 1);
		to_be_encrypted = to_be_encrypted + string(padding);
		to_be_encrypted.erase( remove(to_be_encrypted.begin(), to_be_encrypted.end(), '\n'), to_be_encrypted.end() );
		return to_be_encrypted;
	}
	else return "0";
	
}

void sendMsg(int sockfd){
	
	struct package
	{
		char sender_session_id[2048];
		char recipient_session_id[2048];
		int msg_len;
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	}data;
	
	char msg_out[512];
	string to_be_encrypted;
	
	db_get_id("USER");
	string session_id = key_data.id;
	
	db_getKey_client(session_id, "USER");
	string sender_auth_key = key_data.auth_key;

	strncpy(data.sender_session_id, session_id.c_str(), 64);	
	
	while(!feof(stdin))
	{
		fgets(msg_out, 512, stdin);
		// ENCRYPTION 
		to_be_encrypted = getEncryptedBlock(session_id, string(msg_out)); // формирование to be encrypted block
		data.msg_len = string(msg_out).length() - 1;

		strncpy(data.msg_key, get_msg_key(to_be_encrypted, sender_auth_key).c_str(), 2048);
		
		string aes_key = get_aes_key(string(data.msg_key), sender_auth_key);
		string aes_iv = get_aes_iv(string(data.msg_key), sender_auth_key);
		
		strncpy(data.encrypted_data, AES256Encode(to_be_encrypted, aes_key, aes_iv).c_str(), 2048);
		
		#ifdef SEE
		string buff = string(data.encrypted_data);
		cout << "--------------------------------------+" << endl;
		cout << "Field "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) encrypting information" << endl;
		if (buff.length() > 15){
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
			cout << "enc_msg: " << buff.substr(0, BORDER) << "..." << buff.substr(buff.length()-BORDER) << endl;}
		else
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

void getMsg(int sockfd){
	
	struct package
	{
		char sender_session_id[2048];
		char recipient_session_id[2048];
		int msg_len;
		//string auth_key_id;
		char msg_key[2048];
		char encrypted_data[2048];
	}data;
	
	int recv_len;
	string to_be_encrypted;
	
	db_get_id("USER");
	string session_id = key_data.id;
	
	db_getKey_client(string(session_id), "USER");
	string auth_key = key_data.auth_key;
	
	while(1)
	{
		recv_len = recv(sockfd, &data, sizeof(data), 0);
		// DECRYPTION
		
		string aes_key = get_aes_key(string(data.msg_key), auth_key);
		string aes_iv = get_aes_iv(string(data.msg_key), auth_key);
		string decrypted_data = AES256Decode(data.encrypted_data, aes_key, aes_iv);
// 		cout << decrypted_data << endl;
		
		#ifdef SEE
		string buff = string(data.encrypted_data);
		cout << "--------------------------------------+" << endl;
		cout << "Field "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) got new data from server, decrypting data" << endl;
		if (buff.length() > 15){
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
			cout << "enc_msg: " << buff.substr(0, BORDER) << "..." << buff.substr(buff.length()-BORDER) << endl;}
		else
			cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | " << "enc_msg: " << data.encrypted_data << endl;
		cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << endl;
		cout << "aes_iv " << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl;
		cout << "--------------------------------------+" << endl;
		#endif // SEE
		
		cout << "> " << decrypted_data.substr(38, data.msg_len) + "\n";
		//cout << "> " << decrypted_data;
	}
	//close (sockfd);
}
/* -------------------------==[end: work with messages]==------------------------- */


/* -------------------------==[work with clients]==------------------------- */
int main(int argc, char **argv){
	
	if (argc != 3) { printf("client: invalid data\n"); exit(1); }
	cout << "MTproto: cloud chat (server-client encryption)" << endl << endl;
	
	db_createTable_client("USER");
	db_delAll("USER");    // очистка бд
	
	// генерируем PublicKey PrivateKey клиента
	RSAkeyGen("keys/rsa-client-public.key", "keys/rsa-client-private.key");
	
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
	
	getNewSession_client(sockfd);
	db_get_id("USER");
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

	thread msg_receiving_stream(getMsg, sockfd);     // поток для обработки входящих сообщений
	thread msg_sending_stream(sendMsg, sockfd);    // поток для обработки исходящих сообщений

	msg_receiving_stream.join();
	msg_sending_stream.join();

	db_delUser_client(session_id, "USER");
    close(sockfd);

    return 0;
}
