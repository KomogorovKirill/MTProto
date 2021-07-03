all: server client
	
server:
	g++ src/server.cpp -o server -lgmpxx -lgmp -pthread -lcryptopp -lsqlite3
client:
	g++ src/client.cpp -o client -lgmpxx -lgmp -pthread -lcryptopp -lsqlite3

