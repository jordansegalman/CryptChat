#ifndef CRYPTCHATCLIENT_H
#define CRYPTCHATCLIENT_H

int create_socket();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx, char *cert_file, char *key_file);
void show_certificates(SSL *ssl);
void send_message(const char *message);
void run_client();

#endif /* CRYPTCHATCLIENT_H */
