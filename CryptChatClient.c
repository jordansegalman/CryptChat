#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "CryptChatClient.h"

#define CONFIG "client_config"
#define MAX_RESPONSE 1024

/*
 * Client configuration struct
 */

struct config {
	char *address;	// server address
	int port;	// server port
	char *cert;	// client certificate
	char *key;	// client key
	char *ca;	// ca certificate
};

struct config client_config;	// client configuration

/*
 * @brief Calls client configuration function and prints welcome message
 */

void initialize() {
	parse_config();
	printf("Welcome to CryptChat!\n");
}

/*
 * @brief Parses client configuration file
 */

void parse_config() {
	FILE *config_file = fopen(CONFIG, "r");
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	if (config_file != NULL) {
		while ((read = getline(&line, &len, config_file)) != -1) {
			char *delim = strchr(line, ' ');
			int n = delim - line;
			if (!strncmp(line, "Certificate", n)) {
				client_config.cert = (char *) malloc(sizeof(char) * (strlen(line) - n - 1));
				strncpy(client_config.cert, delim + 1, strlen(line) - n - 2);
				client_config.cert[strlen(line) - n - 2] = '\0';
			} else if (!strncmp(line, "Address", n)) {
				client_config.address = (char *) malloc(sizeof(char) * (strlen(line) - n - 1));
				strncpy(client_config.address, delim + 1, strlen(line) - n - 2);
				client_config.address[strlen(line) - n - 2] = '\0';
			} else if (!strncmp(line, "Port", n)) {
				char *p = (char *) malloc(sizeof(char) * (strlen(line) - n - 1));
				strncpy(p, delim + 1, strlen(line) - n - 2);
				p[strlen(line) - n - 2] = '\0';
				client_config.port = atoi(p);
				free(p);
				p = NULL;
			} else if (!strncmp(line, "Key", n)) {
				client_config.key = (char *) malloc(sizeof(char) * (strlen(line) - n - 1));
				strncpy(client_config.key, delim + 1, strlen(line) - n - 2);
				client_config.key[strlen(line) - n - 2] = '\0';
			} else if (!strncmp(line, "CA", n)) {
				client_config.ca = (char *) malloc(sizeof(char) * (strlen(line) - n - 1));
				strncpy(client_config.ca, delim + 1, strlen(line) - n - 2);
				client_config.ca[strlen(line) - n - 2] = '\0';
			}
		}
		fclose(config_file);
		if (line) {
			free(line);
			line = NULL;
		}
	} else {
		fprintf(stderr, "Could not open client configuration file \'%s\'.\n", CONFIG);
		exit(EXIT_FAILURE);
	}
}

/*
 * @brief Cleans up the client by freeing memory allocated for global variables
 */

void terminate() {
	free(client_config.address);
	client_config.address = NULL;
	free(client_config.cert);
	client_config.cert = NULL;
	free(client_config.key);
	client_config.key = NULL;
	free(client_config.ca);
	client_config.ca = NULL;
}

/*
 * @brief Creates client socket
 *
 * @return File descriptor for created client socket
 */

int create_socket() {
	struct sockaddr_in socketAddress;
	memset(&socketAddress, 0, sizeof(socketAddress));
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_port = htons(client_config.port);
	socketAddress.sin_addr.s_addr = inet_addr(client_config.address);

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

/*
 * @brief Creates client SSL context
 *
 * @return Pointer to created client SSL context
 */

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

/*
 * @brief Configures the client SSL context using the client certificate, client key,
 * and ca certificate
 *
 * @param ctx Client SSL context to configure
 */

void configure_context(SSL_CTX *ctx) {
	if (SSL_CTX_load_verify_locations(ctx, client_config.ca, NULL) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate_file(ctx, client_config.cert, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, client_config.key, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_check_private_key(ctx) != 1) {
		perror("Private key does not match public certificate");
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

/*
 * @brief Shows SSL connection and server certificate information
 *
 * @param ssl Client SSL structure
 */

void show_ssl_info(SSL *ssl) {
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

/*
 * @brief Attempt SSL connection to server, send message to server, and read server
 * response
 *
 * @param new_client Client information struct
 */

void send_message(const char *message) {
	SSL_CTX *ctx = create_context();
	configure_context(ctx);
	int sock = create_socket();
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);

	if (SSL_connect(ssl) < 0) {
		ERR_print_errors_fp(stderr);
	} else {
		printf("Connected to server.\n");
		show_ssl_info(ssl);

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

/*
 * @brief Call functions to initialize client, send message to server, and cleanup
 * and terminate client
 */

void run_client() {
	initialize();
	send_message("CLIENT MESSAGE");
	terminate();
}

int main() {
	run_client();
}
