#include <sqlite3.h>

/* -------------------------==[work with database]==------------------------- */
struct db_key{
	string id;
	string auth_key;
} key_data;

static int callback_key(void *NotUsed, int argc, char **argv, char **azColName) 
{
	//for(int i = 0; i<argc; i++) printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	key_data.auth_key = argv[0];
	return 0;
}
static int callback_id(void *NotUsed, int argc, char **argv, char **azColName) 
{
	//for(int i = 0; i<argc; i++) printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	key_data.id = argv[0];
	return 0;
}
static int callback_debug(void *NotUsed, int argc, char **argv, char **azColName) 
{
	for(int i = 0; i<argc; i++) printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	//key_data.auth_key = argv[0];
	printf("\n");
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void createTable_s(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	/* Создание таблицы для данных пользователей */
	string sql = "CREATE TABLE IF NOT EXISTS "+table_name+" ("          \
	"SOCK_ID            CHAR(64)            NOT NULL," \
	"SESSION_ID         CHAR(64)            NOT NULL," \
	"AUTH_KEY           CHAR(2048)          NOT NULL);"; 
	
	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);
	
	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "Table create successfully\n");
	
	sqlite3_close(db);
}
void createTable_c(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	/* Создание таблицы для данных пользователей */
	string sql = "CREATE TABLE IF NOT EXISTS "+table_name+" ("          \
	"SESSION_ID         CHAR(64)            NOT NULL," \
	"AUTH_KEY           CHAR(2048)          NOT NULL);"; 
	
	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);
	
	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "Table create successfully\n");
	
	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////

void insert_db_s(int sock_id, string id, string auth_key, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	
	string sql = "INSERT INTO "+ table_name +" (SOCK_ID,SESSION_ID,AUTH_KEY) VALUES (" + std::to_string(sock_id) +"," + id + ",'" + auth_key + "'); ";
	//cout << sql << endl;
	
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);
	
	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "value inserted successfully\n");
	
	sqlite3_close(db);
}
void insert_db_c(string id, string auth_key, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	
	string sql = "INSERT INTO "+ table_name +" (SESSION_ID,AUTH_KEY) VALUES (" + id + ",'" + auth_key + "'); ";
	//cout << sql << endl;
	
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);
	
	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "value inserted successfully\n");
	
	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////


void check_db(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	string sql = "SELECT * from " + table_name;
	
	rc = sqlite3_exec(db, sql.c_str(), callback_debug, 0, &zErrMsg);
	
	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "value checked successfully\n");

	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////

void getKey_db_s(int sock_id, string id, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	string sql = "SELECT AUTH_KEY from "+ table_name +" where SOCK_ID=" + std::to_string(sock_id) + "; ";
	
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);
	
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "value get successfully\n");
	

	sqlite3_close(db);
}
void getKey_db_c(string id, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	string sql = "SELECT AUTH_KEY from "+ table_name +" where SESSION_ID=" + id + "; ";
	
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);
	
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "value get successfully\n");
	
	
	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////

void getId_db(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	string sql = "SELECT * from "+ table_name +";";
	
	rc = sqlite3_exec(db, sql.c_str(), callback_id, 0, &zErrMsg);
	
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "value get successfully\n");
	
	
	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////

void delUser_db_s(int sock_id, string id, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	string sql = "DELETE from "+ table_name +" where SOCK_ID=" + std::to_string(sock_id) + "; ";
	
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);
	
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "value deleted successfully\n");

	sqlite3_close(db);
}

void delAll_db(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	string sql = "DELETE from "+ table_name + ";";
	
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);
	
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "value deleted successfully\n");
	
	sqlite3_close(db);
}

void delUser_db_c(string id, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	
	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");
	
	string sql = "DELETE from "+ table_name +" where SESSION_ID=" + id + "; ";
	
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);
	
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} 
	//else fprintf(stdout, "value deleted successfully\n");
	
	sqlite3_close(db);
}
/* -------------------------==[end: work with database]==------------------------- */ 
