#! /usr/bin/env bash

if [[ $# != 3 ]]
then
	echo "Using: $0 <folder with client1> <folder with client2> <folder with server>"
	exit
fi

sudo apt-get install build-essential
sudo apt-get install libgmp3-dev
sudo apt-get install libpthread-stubs0-dev
sudo apt-get install libcrypto++-dev
sudo apt-get install sqlite3 libsqlite3-dev

make
if [[ $? != 0 ]]
then
	echo "Error compiling!"
	exit
fi

if [[ -e $1 ]]
then
	echo "$1 exists!"
	rm -rf client
	rm -rf server
	exit
else
	mkdir $1
fi

if [[ -e $2 ]]
then
	echo "$2 exists!"
	rm -rf $1
	rm -rf client
	rm -rf server
	exit
else
	mkdir $2
fi

if [[ -e $3 ]]
then
	echo "$3 exists!"
	rm -rf $1
	rm -rf $2
	rm -rf client
	rm -rf server
	exit
else
	mkdir $3
fi

cp server $3
cd $3
./server keygen
cd ..

cp client $1
cp $3/rsa-server-public.key $1

cp client $2
cp $3/rsa-server-public.key $2

rm -rf client
rm -rf server
rm -rf $3/rsa-server-public.key
