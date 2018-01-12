all: CryptChatClient CryptChatServer

CryptChatClient: CryptChatClient.c
	gcc -o CryptChatClient CryptChatClient.c -lssl -lcrypto

CryptChatServer: CryptChatServer.c
	gcc -o CryptChatServer CryptChatServer.c -lssl -lcrypto

clean:
	rm CryptChatClient CryptChatServer
