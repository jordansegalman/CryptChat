all: CryptChatClient CryptChatServer

CryptChatClient: CryptChatClient.c
	gcc -o CryptChatClient CryptChatClient.c

CryptChatServer: CryptChatServer.c
	gcc -o CryptChatServer CryptChatServer.c

clean:
	rm CryptChatClient CryptChatServer
