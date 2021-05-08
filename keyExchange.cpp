/* 
 * Создание auth_key 
 * Для клиента и сервера функции немного отличаются
 */
//#define SEE
#define BORDER 6
/* -------------------------==[auth_key key exchange (DH+RAW_RSA)]==------------------------- */
void new_session_server(int sockfd)
{
	printf("starting auth key initialisation\n");
	
	struct dhparams{
		char session_id[64];
		//uint8_t publicKey[1024];
		char p[2048];
		char g[64];
		char A[2048];
		//int magic;
	};
	
	struct dhparams params;
	
	//byte publicKey[292];
	/* принимаем запрос на начало генерации сессионного ключа */
	//recv(sockfd, &publicKey, sizeof(publicKey), 0);
	//for(int i = 0; i < 292; i++) printf("%d ", publicKey[i]);
	
	static char session_id[64];
	while (1){
		getDigit(session_id, 64, 0, 10);
		//cout << "b: " << a << endl;
		if (!strcmp("0", session_id)) { memset(session_id, '\0', 64); continue;}
		else break;
	}
	strcpy(params.session_id, session_id);
	
	/* запоминаем ключ клиента и id сессии*/
	//char client_key[1024];
	//strcpy(client_key, params.publicKey);
	//FILE *data = fopen("rsa-client-public.key", "w");
	//if (data == NULL) exit(1);
	//fwrite(publicKey, 1024, 1, data);
	//fclose(data);
	
	/* генерируем число p */
	char p[2048];
	getDigit(p, 512, 1, 10);
	strcpy(params.p, p);
	
	/* генерируем число g */
	static char g[64];
	getDigit(g, 64, 1, 10);
	strcpy(params.g, g);
	
	/* генерируем секретное число а */
	static char a[64];
	while (1)
	{
		getDigit(a, 64, 0, 10);
		if (!strcmp("0", a)) { memset(a, '\0', 64); continue;}
		else break;
	}
	
	/* генерируем число A, шифруем и отправляем клиенту */
	mpz_t A_mpz; mpz_init(A_mpz);
	mpz_t p_mpz; mpz_init_set_str(p_mpz, p, 10);
	mpz_t g_mpz; mpz_init_set_str(g_mpz, g, 10);
	mpz_t a_mpz; mpz_init_set_str(a_mpz, a, 10);
	
	mpz_powm(A_mpz, g_mpz, a_mpz, p_mpz);
	
	static char A[2048];
	mpz_get_str(A, 10, A_mpz);
	
	strcpy(params.A, RSA_Encrypt(A, "rsa-client-public.key").c_str());
	
	#ifdef SEE
	cout << "a: " << string(a).substr(0, BORDER) << "..." << string(a).substr(strlen(a)-BORDER) << endl;
	cout << "p: " << string(p).substr(0, BORDER) << "..." << string(p).substr(strlen(p)-BORDER) << endl;
	cout << "g: " << string(g).substr(0, BORDER) << "..." << string(g).substr(strlen(g)-BORDER) << endl;
	cout << "A: " << string(A).substr(0, BORDER) << "..." << string(A).substr(strlen(A)-BORDER) << endl;
	cout << "decrypted A: " << string(params.A).substr(0, BORDER) << "..." << string(params.A).substr(strlen(params.A)-BORDER) << endl << endl;
	#endif // SEE
	
	send(sockfd, &params, sizeof(params), 0);
	
	/* принимаем от пользователя число B и расшифровываем */
	recv(sockfd, &params, sizeof(struct dhparams), 0);
	
	/* запоминаем число B */
	static char B[2048];
	strcpy(B, RSA_Decrypt(params.A, "rsa-server-private.key").c_str());
	
	#ifdef SEE
	cout << "B: " << string(params.A).substr(0, BORDER) << "..." << string(params.A).substr(strlen(params.A)-BORDER) << endl;
	cout << "decrypted B: " << string(B).substr(0, BORDER) << "..." << string(B).substr(strlen(B)-BORDER) << endl;
	#endif // SEE
	
	mpz_t B_mpz; mpz_init(B_mpz);
	mpz_init_set_str(B_mpz, B, 10);
	
	/* вычисляем auth_key */
	mpz_t auth_key_mpz; mpz_init(auth_key_mpz);
	mpz_powm(auth_key_mpz, B_mpz, a_mpz, p_mpz);
	
	static char auth_key[2048];
	mpz_get_str(auth_key, 10, auth_key_mpz);
	
	/* открываем файл, куда будет записан auth_key c определяющим параметром session_id */
	// запись в бд
	insert_db_s(sockfd, string(session_id), string(auth_key), "USERS");
	
	printf("successfully authorization | new session with id: %s\n\n", session_id);

	#ifdef SEE
	cout << "now database contains:" << endl;
	check_db("USERS");
	#endif // SEE
}

void new_session_client(int sockfd){
	
	printf("starting new session\n");
	
	struct dhparams{
		char session_id[64];
		//uint8_t publicKey[1024];
		char p[2048];
		char g[64];
		char A[2048];
		//int magic;
	};
	
	struct dhparams params;
	
	// генерируем секретное число b
	static char b[64];
	while (1){
		getDigit(b, 64, 0, 10);
		//cout << "b: " << a << endl;
		if (!strcmp("0", b)) { memset(b, '\0', 64); continue;}
		else break;
	}
	
	// записываем в структуру публичный ключ клиента
	// отправить публичный ключ на сервер - ?
	
	//отправляем запрос на начало генерации сессионного ключа
	//send(sockfd, &publicKey, sizeof(publicKey), 0);
	
	// принимаем от сервера числа p, g, A
	recv(sockfd, &params, sizeof(params), 0);
	
	/* запоминаем session_id */
	static char session_id[64];
	strcpy(session_id, params.session_id);
	
	#ifdef SEE
	cout << "b: " << string(b).substr(0, BORDER) << "..." << string(b).substr(strlen(b)-BORDER) << endl;
	cout << "p: " << string(params.p).substr(0, BORDER) << "..." << string(params.p).substr(strlen(params.p)-BORDER) << endl;
	cout << "g: " << string(params.g).substr(0, BORDER) << "..." << string(params.g).substr(strlen(params.g)-BORDER) << endl;
	cout << "A: " << string(params.A).substr(0, BORDER) << "..." << string(params.A).substr(strlen(params.A)-BORDER) << endl;
	#endif // SEE
	
	// запоминаем число А
	static char A[2048];
	strcpy(A, RSA_Decrypt(params.A, "rsa-client-private.key").c_str());
	
	#ifdef SEE
	cout << "decrypted A: " << string(A).substr(0, BORDER) << "..." << string(A).substr(strlen(A)-BORDER) << endl;
	cout << "session_id: " << string(params.session_id).substr(0, BORDER) << "..." << string(params.session_id).substr(strlen(params.session_id)-BORDER) << endl << endl;
	#endif // SEE
	
	// запоминаем число p
	char p[2048];
	strcpy(p, params.p);
	
	// запоминаем число g
	static char g[64];
	strcpy(g, params.g);
	
	// генерируем число В, шифруем и отправляем серверу
	static mpz_t B_mpz; mpz_init(B_mpz);
	mpz_t p_mpz; mpz_init_set_str(p_mpz, p, 10);
	mpz_t g_mpz; mpz_init_set_str(g_mpz, g, 10);
	mpz_t b_mpz; mpz_init_set_str(b_mpz, b, 10);
	
	mpz_powm(B_mpz, g_mpz, b_mpz, p_mpz);
	
	static char B[2048];
	mpz_get_str(B, 10, B_mpz);
	strcpy(params.A, RSA_Encrypt(B, "rsa-server-public.key").c_str());
	
	#ifdef SEE
	cout << "B: " << string(B).substr(0, BORDER) << "..." << string(B).substr(strlen(B)-BORDER) << endl;
	cout << "ecrypted B: " << string(params.A).substr(0, BORDER) << "..." << string(params.A).substr(strlen(params.A)-BORDER) << endl << endl;
	#endif // SEE
	
	send(sockfd, &params, sizeof(struct dhparams), 0);
	
	// вычисляем auth_key
	mpz_t A_mpz; mpz_init(A_mpz);
	mpz_init_set_str(A_mpz, A, 10);
	
	mpz_t auth_key_mpz; mpz_init(auth_key_mpz);
	mpz_powm(auth_key_mpz, A_mpz, b_mpz, p_mpz);
	
	char auth_key[2048];
	mpz_get_str(auth_key, 10, auth_key_mpz);
	
	/* сохранить auth_key и сохранить id */
	insert_db_c(string(session_id), string(auth_key), "USER");
	
	printf("successfully authorization | session id: %s\n\n", session_id);

	#ifdef SEE
	cout << "now database contains:" << endl;
	check_db("USER");
	#endif // SEE
}

/* -------------------------==[end: auth_key key exchange (DH+RAW_RSA)]==------------------------- */ 
