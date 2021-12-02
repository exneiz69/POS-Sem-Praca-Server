#include "data.h"
#include "Server.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

void *threadMain(void *pData) {
    printf("start socket in thread\n");
    int *newSocketFD = (int *) pData;
    int n;

    if (*newSocketFD < 0) {
        perror("ERROR on accept");
    }

    Action action;
    n = read(*newSocketFD, &action, sizeof(Action));
    if (n < 0) {
        perror("Error reading from socket");
    }

    Reply reply;
    switch(action) {
        case Action::RegisterAccount:
            reply = Server::getInstance().registerNewUser(*newSocketFD);
            break;
        case Action::DeleteAccount:
            reply = Server::getInstance().unregisterUser(*newSocketFD);
            break;
        case Action::Login:
            reply = Server::getInstance().authorizeUser(*newSocketFD);
            break;
        case Action::Logout:
            reply = Server::getInstance().deauthorizeUser(*newSocketFD);
            break;
        case Action::SendMessage:
            reply = Server::getInstance().getMessage(*newSocketFD);
            break;
        case Action::GetNewMessages:
            reply = Server::getInstance().sendNewMessages(*newSocketFD);
            break;
        default:
            break;
    }

    n = write(*newSocketFD, &reply, sizeof(Reply));
    if (n < 0) {
        perror("Error writing to socket");
    }

    printf("end socket in thread\n");

    close(*newSocketFD);

    delete newSocketFD;

    return NULL;
}

int main(int argc, char *argv[]) {
    int socketFD;
    int newSocketFD;
    socklen_t clientAddressLength;
    struct sockaddr_in serverAddress;
    struct sockaddr_in clientAddress;

    if (argc < 2) {
        fprintf(stderr, "usage %s port\n", argv[0]);
        return 1;
    }

    bzero((char *) &serverAddress, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(atoi(argv[1]));

    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        perror("Error creating socket");
        return 1;
    }

    if (bind(socketFD, (sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("Error binding socket address");
        return 2;
    }

    listen(socketFD, 5);
    clientAddressLength = sizeof(clientAddress);

    pthread_t thread[20];

    pthread_attr_t threadAttr;
    pthread_attr_init(&threadAttr);
    pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);

    for (int i = 0; i < 20; i++) {
        printf("waiting socket %d\n", i);
        newSocketFD = accept(socketFD, (sockaddr *) &clientAddress, &clientAddressLength);
        printf("accepted socket %d\n", i);
        pthread_create(&thread[i], &threadAttr, &threadMain, new int(newSocketFD));
    }

    pthread_attr_destroy(&threadAttr);

    close(socketFD);

    return 0;
}