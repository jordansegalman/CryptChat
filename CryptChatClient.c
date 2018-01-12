#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "CryptChatClient.h"

#define MAX_RESPONSE 1024

char *address;
int port;

int create_socket() {
	struct sockaddr_in socketAddress;
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_addr.s_addr = inet_addr(address);
	socketAddress.sin_port = htons(port);
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	if (connect(sock, (struct sockaddr *) &socketAddress, sizeof(socketAddress)) < 0) {
		perror("connection failed");
		exit(EXIT_FAILURE);
	}
	return sock;
}

void send_message(const char *message, char *response) {
	int sock = create_socket();
	send(sock, message, strlen(message), 0);
	recv(sock, response, MAX_RESPONSE, 0);
	close(sock);
}

void run_client() {
	printf("Welcome to CryptChat!\n");
	char response[MAX_RESPONSE];
	send_message("CLIENT MESSAGE", response);
	printf("%s\n", response);
}

int main() {
	address = (char *) malloc(strlen("127.0.0.1") + 1);
	strcpy(address, "127.0.0.1");
	port = 33333;
	run_client();
}
