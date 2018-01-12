#ifndef CryptChatClient
#define CryptChatClient

int create_socket();
void send_message(const char *message, char *response);
void run_client();

#endif
