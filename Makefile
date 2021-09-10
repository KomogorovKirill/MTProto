all: server client
	
server: src/server.cpp
	@g++ src/server.cpp -o server -lgmpxx -lgmp -pthread -lcryptopp -lsqlite3
client: src/client.cpp
	@g++ src/client.cpp -o client -lgmpxx -lgmp -pthread -lcryptopp -lsqlite3

