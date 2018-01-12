#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "CryptChatServer.h"

#define MAX_MESSAGE 1024

int create_socket(int port) {
	struct sockaddr_in socketAddress; 
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_addr.s_addr = INADDR_ANY;
	socketAddress.sin_port = htons(port);
	int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	int opt = 1; 
	if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt))) {
		perror("setting socket options failed");
		exit(EXIT_FAILURE);
	}
	if (bind(serverSocket, (struct sockaddr *) &socketAddress, sizeof(socketAddress)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(serverSocket, 10) < 0) {
		perror("listen failed");
		exit(EXIT_FAILURE);
	}
	return serverSocket;
}

void process_message(int clientSocket) {
	char message[MAX_MESSAGE];
	recv(clientSocket, message, MAX_MESSAGE, 0);
	printf("%s\n", message);
	const char *response = "SERVER RESPONSE";
	send(clientSocket, response, strlen(response), 0);
	close(clientSocket);
}

void run_server(int port) {
	int serverSocket = create_socket(port);
	printf("Waiting for connections...\n");
	while (1) {
		struct sockaddr_in clientAddress;
		int client_socklen = sizeof(clientAddress);
		int clientSocket = accept(serverSocket, (struct sockaddr *) &clientAddress, (socklen_t*) &client_socklen);
		if (clientSocket < 0) {
			perror("accept client failed");
			exit(EXIT_FAILURE);
		}
		process_message(clientSocket);
	}	
}

int main() {
	run_server(33333);
}
