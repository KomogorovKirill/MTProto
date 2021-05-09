 /* -------------------------==[message encryption]==------------------------- */
  
 string get_msg_key(string plaintext, string auth_key)
 {
	 /*
	  *	Message Key (msg_key)
	  *	In MTProto 2.0, the middle 128 bits of the SHA-256 hash of the message to be encrypted (including the internal 
	  *	header and the padding bytes for MTProto 2.0), prepended by a 32-byte fragment of the authorization key.
	  */
	 
	 string msg_key_large = SHA256(auth_key.substr(0+0, 32) + plaintext);
	 string msg_key = msg_key_large.substr(8, 16);
	 //cout << msg_key << endl;
	 return msg_key;
	 
	 
 }
 
 string get_aes_key(string msg_key, string auth_key)
 {
	 /*
	  * The 2048-bit authorization key (auth_key) and the 128-bit message key (msg_key) are used to compute a 256-bit 
	  * AES key (aes_key) and a 256-bit initialization vector (aes_iv) which are subsequently used to encrypt the part of the message to be encrypted
	  */
	 
	 string sha256_a = SHA256 (msg_key + auth_key.substr(0, 36));
	 string sha256_b = SHA256 (auth_key.substr(40+0, 36) + msg_key);
	 string aes_key = sha256_a.substr(0, 8) + sha256_b.substr(8, 16) + sha256_a.substr(24, 8);
	 //cout << aes_key << endl;
	 return aes_key;
 }
 
 string get_aes_iv(string msg_key, string auth_key)
 {
	 /*
	  * The 2048-bit authorization key (auth_key) and the 128-bit message key (msg_key) are used to compute a 256-bit 
	  * AES key (aes_key) and a 256-bit initialization vector (aes_iv) which are subsequently used to encrypt the part of the message to be encrypted
	  */
	 
	 string sha256_a = SHA256 (msg_key + auth_key.substr(0, 36));
	 string sha256_b = SHA256 (auth_key.substr(40+0, 36) + msg_key);
	 string aes_iv = sha256_b.substr(0, 8) + sha256_a.substr(8, 16) + sha256_b.substr(24, 8);
	 //cout << aes_key << endl;
	 return aes_iv;
 }
 
 /*
   
  //client1 side
  data.msg_key = get_msg_key("hello", "1689201510339294387298507013777477709713353866798396524369556698038440367397505412943061173051475961146102960013304351330203196411206879965450211253658516");
  string aes_key = get_aes_key(data.msg_key, "1689201510339294387298507013777477709713353866798396524369556698038440367397505412943061173051475961146102960013304351330203196411206879965450211253658516");
  string aes_iv = get_aes_iv(data.msg_key, "1689201510339294387298507013777477709713353866798396524369556698038440367397505412943061173051475961146102960013304351330203196411206879965450211253658516");
  
  data.encrypted_data = AES256Encode("hello", aes_key, aes_iv);
  
  //server side
  aes_key = get_aes_key(data.msg_key, "1689201510339294387298507013777477709713353866798396524369556698038440367397505412943061173051475961146102960013304351330203196411206879965450211253658516");
  aes_iv = get_aes_iv(data.msg_key, "1689201510339294387298507013777477709713353866798396524369556698038440367397505412943061173051475961146102960013304351330203196411206879965450211253658516");
  
  string decryted_data = AES256Decode(data.encrypted_data, aes_key, aes_iv);
  
  aes_key = get_aes_key(data.msg_key, "9872201510339294387298507013777477709713353866798396524369556698038440367397505412943061173051475961146102960013304351330203196411206879965450211253651234");
  aes_iv = get_aes_iv(data.msg_key, "9872201510339294387298507013777477709713353866798396524369556698038440367397505412943061173051475961146102960013304351330203196411206879965450211253651234");
  
  data.encrypted_data = AES256Encode(decryted_data, aes_key, aes_iv);
  
  //client 2 side
  aes_key = get_aes_key(data.msg_key, "9872201510339294387298507013777477709713353866798396524369556698038440367397505412943061173051475961146102960013304351330203196411206879965450211253651234");
  aes_iv = get_aes_iv(data.msg_key, "9872201510339294387298507013777477709713353866798396524369556698038440367397505412943061173051475961146102960013304351330203196411206879965450211253651234");
  
  decryted_data = AES256Decode(data.encrypted_data, aes_key, aes_iv);
  cout << decryted_data << endl;
  > hello
  
  */
