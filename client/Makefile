INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/
all:
	gcc -g -I$(INC) -L$(LIB) -o client main.c ../com/*.c ../crypto/*.c -lssl -lcrypto -ldl -lpthread
