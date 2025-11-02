md5crack:
	gcc src/md5crack.c -o md5crack -lpthread -lssl -lcrypto -O3

md5crack-sequential:
	gcc src/md5crack-sequential.c -o md5crack-sequential -lpthread -lssl -lcrypto -O3

md5crack-concurrent:
	gcc src/md5crack-concurrent.c -o md5crack-concurrent -lpthread -lssl -lcrypto -O3

frequency-analyser:
	gcc src/frequency-analyser.c -o frequency-analyser
