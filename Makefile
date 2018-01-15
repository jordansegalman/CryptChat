all: CryptChatClient CryptChatServer

CryptChatClient: CryptChatClient.c
	gcc -Wall -Wextra -o CryptChatClient CryptChatClient.c -lssl -lcrypto

CryptChatServer: CryptChatServer.c
	gcc -Wall -Wextra -o CryptChatServer CryptChatServer.c -lssl -lcrypto -lpthread

clean:
	rm CryptChatClient CryptChatServer
