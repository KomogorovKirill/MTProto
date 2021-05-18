
void prettyCout_1(void)
{
	string e_data = string(data.encrypted_data);
	cout << "--------------------------------------+" << endl;
	cout << "Field "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) decrypting encrypted information" << endl;
	cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
	cout << "enc_msg: " << e_data.substr(0, BORDER) << "..." << e_data.substr(e_data.length()-BORDER) << endl;}
	cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << "from_id " << data.sender_session_id << endl;
	cout << "aes_iv "  << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl << endl;
}

void prettyCout_2(void)
{
	e_data = string(data.encrypted_data);
	cout << "\nField "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) encrypting information with new data" << endl;
	cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
	cout << "enc_msg: " << e_data.substr(0, BORDER) << "..." << e_data.substr(e_data.length()-BORDER) << endl;}
	cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << "send data to sock_id: " << recipient_socket[i] <<  endl;
	cout << "aes_iv "  << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl;
	cout << "--------------------------------------+" << endl << endl;
}

void prettyCout_3(void)
{
	string buff = string(data.encrypted_data);
	cout << "--------------------------------------+" << endl;
	cout << "Field "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) encrypting information" << endl;
	cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
	cout << "enc_msg: " << buff.substr(0, BORDER) << "..." << buff.substr(buff.length()-BORDER) << endl;
	cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << endl;
	cout << "aes_iv " << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl;
	cout << "--------------------------------------+" << endl << endl;
}

void prettyCout_4(void)
{
	string buff = string(data.encrypted_data);
	cout << "--------------------------------------+" << endl;
	cout << "Field "   << setw( 11 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) got new data from server, decrypting data" << endl;
	cout << "msg_key " << setw( 10 ) << " - " << setw( 10 ) << string(data.msg_key).substr(0, BORDER) << "..." << string(data.msg_key).substr(strlen(data.msg_key)-BORDER) << " | ";
	cout << "enc_msg: " << buff.substr(0, BORDER) << "..." << buff.substr(buff.length()-BORDER) << endl;
	cout << "aes_key " << setw( 10 ) << " - " << setw( 10 ) << aes_key.substr(0, BORDER) << "..." << aes_key.substr(aes_key.length()-BORDER) << " | " << endl;
	cout << "aes_iv " << setw( 11 ) << " - " << setw( 10 ) << aes_iv.substr(0, BORDER) << "..." << aes_iv.substr(aes_iv.length()-BORDER) << " | " << endl;
	cout << "--------------------------------------+" << endl;
}

void prettyCoutKeyEx_1(void)
{
	cout << "--------------------------------------+" << endl;
	cout << "Field  "   << setw( 10 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) generating DH params" << endl;
	cout << "a  " << setw( 15 ) << " - " << setw( 10 ) << string(a).substr(0, BORDER) << "..." << string(a).substr(strlen(a)-BORDER) << " | " << endl;
	cout << "p  " << setw( 15 ) << " - " << setw( 10 ) << string(p).substr(0, BORDER) << "..." << string(p).substr(strlen(p)-BORDER) << " | " << endl;
	cout << "g  " << setw( 15 ) << " - " << setw( 10 ) << string(g).substr(0, BORDER) << "..." << string(g).substr(strlen(g)-BORDER) << " | " << endl;
	cout << "A  " << setw( 15 ) << " - " << setw( 10 ) << string(A).substr(0, BORDER) << "..." << string(A).substr(strlen(A)-BORDER) << " | " << endl;
	cout << "enc_A  " << setw( 11 ) << " - " << setw( 10 ) << string(dhparams.A).substr(0, BORDER) << "..." << string(dhparams.A).substr(strlen(dhparams.A)-BORDER) << " | "  << endl;
	cout << "dec dh aes_key  " << setw( 2 ) << " - " << setw( 10 ) << dh_aes_key.substr(0, BORDER) << "..." << dh_aes_key.substr(dh_aes_key.length()-BORDER) << " | " << endl;
	cout << "dec dh aes_iv  " << setw( 3 ) << " - " << setw( 10 ) << dh_aes_iv.substr(0, BORDER) << "..." << dh_aes_iv.substr(dh_aes_iv.length()-BORDER) << " | " << endl;
	cout << "enc dh aes_key  " << setw( 2 ) << " - " << setw( 10 ) << string(dhparams.dh_aes_key).substr(0, BORDER) << "..." << string(dhparams.dh_aes_key).substr(strlen(dhparams.dh_aes_key)-BORDER) << " | ";
	cout << "(!) encrypting aes_key with client pub_key" << endl;
	cout << "enc dh aes_iv  " << setw( 3 ) << " - " << setw( 10 ) << string(dhparams.dh_aes_iv).substr(0, BORDER) << "..." << string(dhparams.dh_aes_iv).substr(strlen(dhparams.dh_aes_iv)-BORDER) << " | ";
	cout << "(!) encrypting aes_key with client pub_key" << endl;
	cout << "--------------------------------------+" << endl << endl;
}

void prettyCoutKeyEx_2(void)
{
	cout << "--------------------------------------+" << endl;
	cout << "Field  "   << setw( 10 )  << "Length" << setw( 10 )<<  "Value" << setw(13) << " | " << "(!) data from client" << endl;
	cout << "enc_B  " << setw( 11 ) << " - " << setw( 10 ) << string(dhparams.A).substr(0, BORDER) << "..." << string(dhparams.A).substr(strlen(dhparams.A)-BORDER) << " | " << endl;
	cout << "B  " << setw( 15 ) << " - " << setw( 10 ) << string(B).substr(0, BORDER) << "..." << string(B).substr(strlen(B)-BORDER) << " | " << endl;
	cout << "--------------------------------------+" << endl << endl;
}

void prettyCoutKeyEx_3(void)
{
	cout << "now database contains:" << endl;
	check_db("USERS");
	cout << endl;
}

void prettyCoutKeyEx_4(void)
{
	cout << "--------------------------------------+" << endl;
	cout << "Field  " << setw( 10 )  << "Length" << setw( 10 ) << "Value" << setw(13) << " | " << "(!) DH params from server" << endl;
	cout << "b  " << setw( 15 ) << " - " << setw( 10 ) << string(b).substr(0, BORDER) << "..." << string(b).substr(strlen(b)-BORDER) << " | " << endl;
	cout << "p  " << setw( 15 ) << " - " << setw( 10 )<< string(dhparams.p).substr(0, BORDER) << "..." << string(dhparams.p).substr(strlen(dhparams.p)-BORDER) << " | " << endl;
	cout << "g  " << setw( 15 ) << " - " << setw( 10 )<< string(dhparams.g).substr(0, BORDER) << "..." << string(dhparams.g).substr(strlen(dhparams.g)-BORDER) << " | " << endl;
	cout << "enc_A  " << setw( 11 ) << " - " << setw( 10 )<< string(dhparams.A).substr(0, BORDER) << "..." << string(dhparams.A).substr(strlen(dhparams.A)-BORDER) << " | " << endl;
	cout << "--------------------------------------+" << endl << endl;
}

void prettyCoutKeyEx_5(void)
{
	cout << "--------------------------------------+" << endl;
	cout << "Field  " << setw( 10 )  << "Length" << setw( 10 ) << "Value" << setw(13) << " | " << "(!) decrypt rsa param A" << endl;
	cout << "A  " << setw( 15 ) << " - " << setw( 10 ) << string(A).substr(0, BORDER) << "..." << string(A).substr(strlen(A)-BORDER) << " | " << endl;
	cout << "dec dh aes_key  " << setw( 2 ) << " - " << setw( 10 ) << dh_aes_key.substr(0, BORDER) << "..." << dh_aes_key.substr(dh_aes_key.length()-BORDER) << " | ";
	cout << "(!) decrypting aes_key with client sec_key" << endl;
	cout << "dec dh aes_iv  " << setw( 3 ) << " - " << setw( 10 ) << dh_aes_iv.substr(0, BORDER) << "..." << dh_aes_iv.substr(dh_aes_iv.length()-BORDER) << " | ";
	cout << "(!) decrypting aes_key with client sec_key" << endl;
	cout << "--------------------------------------+" << endl << endl;
}

void prettyCoutKeyEx_6(void)
{
	cout << "--------------------------------------+" << endl;
	cout << "Field  " << setw( 10 )  << "Length" << setw( 10 ) << "Value" << setw(13) << " | " << "(!) calculate rsa param B" << endl;
	cout << "B  " << setw( 15 ) << " - " << setw( 10 ) << string(B).substr(0, BORDER) << "..." << string(B).substr(strlen(B)-BORDER) << " | " << endl;
	cout << "enc_B  "<< setw( 11 ) << " - " << setw( 10 )  << string(dhparams.A).substr(0, BORDER) << "..." << string(dhparams.A).substr(strlen(dhparams.A)-BORDER) << " | " << endl;
	cout << "--------------------------------------+" << endl << endl;
}

void prettyCoutKeyEx_7(void)
{
	cout << "(!) now database contains:" << endl;
	check_db("USER");
	cout << endl;
}
