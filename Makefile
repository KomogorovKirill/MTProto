all: server client
	
server:
	g++ server.cpp -o server -lgmpxx -lgmp -pthread -lcryptopp -lsqlite3
client:
	g++ client.cpp -o client -lgmpxx -lgmp -pthread -lcryptopp -lsqlite3

