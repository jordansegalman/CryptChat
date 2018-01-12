#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "CryptChatServer.h"

#define MAX_MESSAGE 1024

int create_socket(int port) {
	struct sockaddr_in socketAddress; 
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_port = htons(port);
	socketAddress.sin_addr.s_addr = INADDR_ANY;
	int serverSocket = socket(PF_INET, SOCK_STREAM, 0);
	if (serverSocket < 0) {
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}
	if (bind(serverSocket, (struct sockaddr *) &socketAddress, sizeof(socketAddress)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(serverSocket, 10) < 0) {
		perror("Listen failed");
		exit(EXIT_FAILURE);
	}
	return serverSocket;
}

SSL_CTX *create_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void configure_context(SSL_CTX *ctx, char *cert_file, char *key_file) {
	if (SSL_CTX_load_verify_locations(ctx, cert_file, key_file) != 1) {
		ERR_print_errors_fp(stderr);
	}
	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
		ERR_print_errors_fp(stderr);
	}
	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		perror("Private key does not match public certificate");
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

void show_certificates(SSL *ssl) {
	printf ("SSL cipher: %s\n", SSL_get_cipher(ssl));
	X509 *client_cert = SSL_get_peer_certificate(ssl);
	if (client_cert != NULL) {
		printf("Client certificate:\n");
		char *str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
		printf("\tSubject: %s\n", str);
		OPENSSL_free(str);
		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
		printf("\tIssuer: %s\n", str);
		OPENSSL_free(str);
		X509_free(client_cert);
	} else {
		printf("Client does not have certificate\n");
	}
}

void process_message(int clientSocket, SSL *ssl) {
	char message[MAX_MESSAGE] = {0};
	int len;
	if (SSL_accept(ssl) < 0) {
		ERR_print_errors_fp(stderr);
	} else {
		show_certificates(ssl);
		len = SSL_read(ssl, message, MAX_MESSAGE);
		if (len > 0) {
			message[len] = '\0';
			printf("%s\n", message);
			const char *response = "SERVER RESPONSE";
			SSL_write(ssl, response, strlen(response));
		} else {
			ERR_print_errors_fp(stderr);
		}
	}
	SSL_free(ssl);
	close(clientSocket);
}

void run_server(int port) {
	SSL_CTX *ctx;
	ctx = create_context();
	configure_context(ctx, "./CryptChat.crt", "./CryptChat.key");
	int serverSocket = create_socket(port);
	printf("Waiting for connections...\n");
	while (1) {
		struct sockaddr_in clientAddress;
		socklen_t client_socklen = sizeof(clientAddress);
		int clientSocket = accept(serverSocket, (struct sockaddr *) &clientAddress, &client_socklen);
		if (clientSocket < 0) {
			perror("Accept client failed");
			exit(EXIT_FAILURE);
		}
		SSL *ssl;
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, clientSocket);
		process_message(clientSocket, ssl);
	}
	close(serverSocket);
	SSL_CTX_free(ctx);
	EVP_cleanup();
}

int main() {
	run_server(33333);
}
