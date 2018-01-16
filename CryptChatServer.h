#ifndef CRYPTCHATSERVER_H
#define CRYPTCHATSERVER_H

void initialize();
void parse_config();
void terminate();
void create_server_pass();
void derive_key(const char *pass, unsigned char *out);
int verify_password(const char *pass);
int create_socket();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);
void show_certificates(SSL *ssl);
void *process_message(void *new_client);
void run_server();

#endif /* CRYPTCHATSERVER_H */
