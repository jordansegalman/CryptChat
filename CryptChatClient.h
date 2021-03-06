#ifndef CRYPTCHATCLIENT_H
#define CRYPTCHATCLIENT_H

void initialize();
void parse_config();
void terminate();
int create_socket();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);
void show_ssl_info(SSL *ssl);
void send_message(const char *message);
void run_client();

#endif /* CRYPTCHATCLIENT_H */
