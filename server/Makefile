INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/
al:
	gcc -g -I$(INC) -L$(LIB) -o server main.c ../com/*.c ../crypto/*.c -lssl -lcrypto -ldl -lpthread
