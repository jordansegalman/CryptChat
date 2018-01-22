#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <pthread.h>

#include "CryptChatServer.h"

#define CONFIG "server_config"
#define MAX_MESSAGE 1024
#define KEY_LENGTH 64
#define ITERATIONS 10000
#define DIGEST EVP_sha512()

/*
 * Server configuration struct
 */

struct config {
	int port;	// server port
	char *cert;	// server certificate
	char *key;	// server key
	char *ca;	// ca certificate
};

/*
 * Client information struct
 */

struct client {
	int client_socket;	// client socket
	SSL *ssl;		// client SSL structure
};

struct config server_config;	// server configuration
unsigned char *server_key;	// server key
unsigned char *salt;		// server key salt

/*
 * @brief Calls server configuration and server key creation functions
 */

void initialize() {
	parse_config();
	create_server_key();
}

/*
 * @brief Parses server configuration file
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
				server_config.cert = (char *) malloc(sizeof(char) * (strlen(line) - n - 1));
				strncpy(server_config.cert, delim + 1, strlen(line) - n - 2);
				server_config.cert[strlen(line) - n - 2] = '\0';
			} else if (!strncmp(line, "Port", n)) {
				char *p = (char *) malloc(sizeof(char) * (strlen(line) - n - 1));
				strncpy(p, delim + 1, strlen(line) - n - 2);
				p[strlen(line) - n - 2] = '\0';
				server_config.port = atoi(p);
				free(p);
				p = NULL;
			} else if (!strncmp(line, "Key", n)) {
				server_config.key = (char *) malloc(sizeof(char) * (strlen(line) - n - 1));
				strncpy(server_config.key, delim + 1, strlen(line) - n - 2);
				server_config.key[strlen(line) - n - 2] = '\0';
			} else if (!strncmp(line, "CA", n)) {
				server_config.ca = (char *) malloc(sizeof(char) * (strlen(line) - n - 1));
				strncpy(server_config.ca, delim + 1, strlen(line) - n - 2);
				server_config.ca[strlen(line) - n - 2] = '\0';
			}
		}
		fclose(config_file);
		if (line) {
			free(line);
			line = NULL;
		}
	} else {
		fprintf(stderr, "Could not open server configuration file \'%s\'.\n", CONFIG);
		exit(EXIT_FAILURE);
	}
}

/*
 * @brief Cleans up the server by freeing memory allocated for global variables
 */

void terminate() {
	free(server_key);
	server_key = NULL;
	free(salt);
	salt = NULL;
	free(server_config.cert);
	server_config.cert = NULL;
	free(server_config.key);
	server_config.key = NULL;
	free(server_config.ca);
	server_config.ca = NULL;
}

/*
 * @brief Initializes the salt with KEY_LENGTH random bytes and creates the server
 * key by getting the password as input from user and passing it to derive_key
 */

void create_server_key() {
	server_key = (unsigned char *) malloc(sizeof(unsigned char) * KEY_LENGTH);
	salt = (unsigned char *) malloc(sizeof(unsigned char) * KEY_LENGTH);
	RAND_bytes(salt, KEY_LENGTH);

	int attempts = 0;
	int server_pass_created = 0;
	while (!server_pass_created) {
		attempts++;
		char *pass = getpass("Enter new server password: ");
		if (pass == NULL) {
			fprintf(stderr, "Getting new password failed\n");
			exit(EXIT_FAILURE);
		}
		derive_key(pass, server_key);
		memset(pass, 0, strlen(pass));

		pass = getpass("Confirm new server password: ");
		if (pass == NULL) {
			fprintf(stderr, "Getting new password failed\n");
			exit(EXIT_FAILURE);
		}

		if (!verify_password(pass)) {
			memset(pass, 0, strlen(pass));
			server_pass_created = 1;
		} else {
			memset(pass, 0, strlen(pass));
			memset(server_key, 0, strlen(server_key));

			if (attempts >= 3) {
				printf("Passwords did not match.\n");
				exit(EXIT_FAILURE);
			}
			printf("Passwords did not match. Please try again.\n");
		}
	}
}

/*
 * @brief Derives a key from a password using the PBKDF2 key derivation function from
 * the OpenSSL library and the salt, ITERATIONS, DIGEST, and KEY_LENGTH
 *
 * @param pass Password to derive key from
 * @param out Output from key derivation
 */

void derive_key(const char *pass, unsigned char *out) {
	if (PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), ITERATIONS, DIGEST, KEY_LENGTH, out) == 0) {
		fprintf(stderr, "Key derivation failed\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * @brief Compares a key derived from a password to the server key
 *
 * @param pass Password to verify
 *
 * @return 0 if success or non-zero if fail
 */

int verify_password(const char *pass) {
	unsigned char *temp_key = (unsigned char *) malloc(sizeof(unsigned char) * KEY_LENGTH);
	derive_key(pass, temp_key);
	int result = memcmp(temp_key, server_key, KEY_LENGTH);
	free(temp_key);
	temp_key = NULL;
	return result;
}

/*
 * @brief Creates server socket
 *
 * @return File descriptor for created server socket
 */

int create_socket() {
	struct sockaddr_in socketAddress; 
	memset(&socketAddress, 0, sizeof(socketAddress));
	socketAddress.sin_family = AF_INET;
	socketAddress.sin_port = htons(server_config.port);
	socketAddress.sin_addr.s_addr = htonl(INADDR_ANY);

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

/*
 * @brief Creates server SSL context
 *
 * @return Pointer to created server SSL context
 */

SSL_CTX *create_context() {
	OPENSSL_init_ssl(0, NULL);
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

/*
 * @brief Configures the server SSL context using the server certificate, server key,
 * and ca certificate
 *
 * @param ctx Server SSL context to configure
 */

void configure_context(SSL_CTX *ctx) {
	SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_load_verify_locations(ctx, server_config.ca, NULL) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate_file(ctx, server_config.cert, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, server_config.key, SSL_FILETYPE_PEM) != 1) {
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
 * @brief Shows SSL connection and client certificate information
 *
 * @param ssl Server SSL structure
 */

void show_ssl_info(SSL *ssl) {
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

/*
 * @brief Accept SSL connection from client, read client message, and send response
 * to client
 *
 * @param new_client Client information struct
 */

void *process_message(void *new_client) {
	struct client *c = (struct client *) new_client;

	if (SSL_accept(c->ssl) < 0) {
		ERR_print_errors_fp(stderr);
	} else {
		printf("Client connected.\n");
		show_ssl_info(c->ssl);

		while (1) {
			char message[MAX_MESSAGE] = {0};
			int len = SSL_read(c->ssl, message, MAX_MESSAGE);
			if (len <= 0) {
				printf("Client disconnected.\n");
				break;
			}
			message[len] = '\0';
			printf("%s\n", message);

			const char *response = "SERVER RESPONSE";
			if (SSL_write(c->ssl, response, strlen(response)) <= 0) {
				printf("Client disconnected.\n");
				break;
			}

			sleep(2);
		}
	}

	SSL_free(c->ssl);
	close(c->client_socket);
	free(c);

	return NULL;
}

/*
 * @brief Call functions to setup server socket and SSL structure and context, wait
 * for client connections, create new thread for each client connection, and call
 * functions to cleanup and terminate server
 */

void run_server() {
	initialize();
	SSL_CTX *ctx = create_context();
	configure_context(ctx);
	int serverSocket = create_socket();

	printf("Waiting for connections...\n");
	while (1) {
		struct sockaddr_in clientAddress;
		socklen_t client_socklen = sizeof(clientAddress);

		int new_client_socket = accept(serverSocket, (struct sockaddr *) &clientAddress, &client_socklen);
		if (new_client_socket < 0) {
			perror("Accept client failed");
			exit(EXIT_FAILURE);
		}

		SSL *new_ssl = SSL_new(ctx);
		SSL_set_fd(new_ssl, new_client_socket);

		struct client *new_client = malloc(sizeof(struct client));
		new_client->client_socket = new_client_socket;
		new_client->ssl = new_ssl;

		pthread_t thread;
		if (pthread_create(&thread, NULL, process_message, (void *) new_client) != 0) {
			perror("Thread creation failed");
			exit(EXIT_FAILURE);
		}
		pthread_detach(thread);
	}

	close(serverSocket);
	SSL_CTX_free(ctx);
	terminate();
}

int main() {
	run_server();
}
