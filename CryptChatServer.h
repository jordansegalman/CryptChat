#ifndef CryptChatServer
#define CryptChatServer

int create_socket(int port);
void process_message(int clientSocket);
void run_server(int port);

#endif
