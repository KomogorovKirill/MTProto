#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

/* -------------------------==[AES256]==------------------------- */
/*
string AES256Encode(string plaintext, unsigned char* key) 
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
	memset(iv, 0x12, CryptoPP::AES::BLOCKSIZE);
	std::string ciphertext;
	
	CryptoPP::AES::Encryption aesEncryption(key, 32);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	
	
	//byte decoded[] = { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
	string encoded;
	
	CryptoPP::StringSource ss((CryptoPP::byte*)ciphertext.c_str(), sizeof((CryptoPP::byte*)ciphertext.c_str()), true,
							  new CryptoPP::Base64Encoder(
								  new CryptoPP::StringSink(encoded)
					) // Base64Encoder
	); // StringSource
	
	cout << encoded << endl;
	
	cout << ciphertext << endl;
	cout << ciphertext.c_str() << endl;
	//string encoded = "/+7dzLuqmYh3ZlVEMyIRAA==";
	string decoded;
	 
	CryptoPP::StringSource ss1(encoded, true,
	 new CryptoPP::Base64Decoder(
		 new CryptoPP::StringSink(decoded)
		 ) // Base64Decoder
		 ); // StringSource
		cout << decoded << endl;
	
	
	return encoded;
}

string AES256Decode(string plaintext, unsigned char* key)
{
	string decoded;
	
	CryptoPP::StringSource ss(plaintext, true,
					new CryptoPP::Base64Decoder(
						new CryptoPP::StringSink(decoded)
					) // Base64Decoder
	); // StringSource
	cout << decoded << endl;
	
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
	memset(iv, 0x12, CryptoPP::AES::BLOCKSIZE);
	std::string decryptiontext;
	CryptoPP::AES::Decryption aesDecryption(key, 32);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptiontext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(decoded.c_str()), decoded.size());
	stfDecryptor.MessageEnd();
	
	

	return decoded;
}*/

std::string AES256Encode(const std::string& str_in, const std::string& key, const std::string& iv)
{
	
	std::string str_out;
	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryption((byte*)key.c_str(), 32, (byte*)iv.c_str());
	CryptoPP::StringSource encryptor(str_in, true,
				new CryptoPP::StreamTransformationFilter(encryption,
				new CryptoPP::Base64Encoder(
				new CryptoPP::StringSink(str_out),
				false // do not append a newline
																			  )
									 )
	);
	return str_out;
}


std::string AES256Decode(const std::string& str_in, const std::string& key, const std::string& iv)
{
	
	std::string str_out;    
	CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryption((byte*)key.c_str(), 32, (byte*)iv.c_str());
	
	CryptoPP::StringSource decryptor(str_in, true,
			new CryptoPP::Base64Decoder(
			new CryptoPP::StreamTransformationFilter(decryption,
			new CryptoPP::StringSink(str_out)
										 )
									 )
	);
	return str_out;
}
/* -------------------------==[end: AES256]==------------------------- */ 
