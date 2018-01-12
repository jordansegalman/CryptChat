#ifndef CRYPTCHATSERVER_H
#define CRYPTCHATSERVER_H

int create_socket(int port);
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx, char *cert_file, char *key_file);
void show_certificates(SSL *ssl);
void process_message(int clientSocket, SSL *ssl);
void run_server(int port);

#endif /* CRYPTCHATSERVER_H */
