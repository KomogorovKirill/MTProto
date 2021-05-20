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

#include "digits.cpp"
#include "sha256.cpp"
#include "rsa.cpp"
#include "aes.cpp"
#include "database.cpp"
#include "keyExchange.cpp"
#include "msg_encr_decr.cpp"

using namespace std;
//#include "pretty_output.cpp"
