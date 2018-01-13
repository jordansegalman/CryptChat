#ifndef CRYPTCHATSERVER_H
#define CRYPTCHATSERVER_H

void initialize();
void terminate();
void create_server_pass();
void derive_key(const char *pass, unsigned char *out);
int verify_password(const char *pass);
int create_socket(int port);
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx, char *cert_file, char *key_file);
void show_certificates(SSL *ssl);
void process_message(int clientSocket, SSL *ssl);
void run_server(int port);

#endif /* CRYPTCHATSERVER_H */
