#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "CryptChatClient.h"

#define MAX_RESPONSE 1024

char *address;
int port;

int create_socket() {
	struct sockaddr_in socketAddress;
	memset(&socketAddress, 0, sizeof(socketAddress));
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_port = htons(port);
	socketAddress.sin_addr.s_addr = inet_addr(address);
	int sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}
	if (connect(sock, (struct sockaddr *) &socketAddress, sizeof(socketAddress)) < 0) {
		perror("Connection failed");
		exit(EXIT_FAILURE);
	}
	return sock;
}

SSL_CTX *create_context() {
	OPENSSL_init_ssl(0, NULL);
	const SSL_METHOD *method = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void configure_context(SSL_CTX *ctx, char *cert_file, char *key_file) {
	if (SSL_CTX_load_verify_locations(ctx, cert_file, key_file) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_check_private_key(ctx) != 1) {
		perror("Private key does not match public certificate");
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

void show_certificates(SSL *ssl) {
	printf("SSL cipher: %s\n", SSL_get_cipher(ssl));
	X509 *server_cert = SSL_get_peer_certificate(ssl);
	if (server_cert != NULL) {
		printf("Server certificate:\n");
		char *str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
		printf("\tSubject: %s\n", str);
		OPENSSL_free(str);
		str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
		printf("\tIssuer: %s\n", str);
		OPENSSL_free(str);
		X509_free(server_cert);
	} else {
		printf("Server does not have certificate\n");
	}
}

void send_message(const char *message) {
	SSL_CTX *ctx = create_context();
	configure_context(ctx, "./CryptChat.crt", "./CryptChat.key");
	int sock = create_socket();
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);
	if (SSL_connect(ssl) < 0) {
		ERR_print_errors_fp(stderr);
	} else {
		printf("Connected to server.\n");
		show_certificates(ssl);
		while (1) {
			if (SSL_write(ssl, message, strlen(message)) <= 0) {
				printf("Connection to server lost.\n");
				break;
			}
			char response[MAX_RESPONSE] = {0};
			int len = SSL_read(ssl, response, MAX_RESPONSE);
			if (len <= 0) {
				printf("Connection to server lost.\n");
				break;
			}
			response[len] = '\0';
			printf("%s\n", response);
			sleep(2);
		}
		SSL_free(ssl);
	}
	close(sock);
	SSL_CTX_free(ctx);
}

void run_client() {
	printf("Welcome to CryptChat!\n");
	send_message("CLIENT MESSAGE");
}

int main() {
	address = (char *) malloc(strlen("127.0.0.1") + 1);
	strcpy(address, "127.0.0.1");
	port = 33333;
	run_client();
}
