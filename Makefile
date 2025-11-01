md5crack:
	gcc src/md5crack.c -o md5crack -lpthread -lssl -lcrypto -O3

frequency-analyser:
	gcc src/frequency-analyser.c -o frequency-analyser
