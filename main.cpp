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
    int *newSocketFD = (int *) pData;
    std::cout << "start socket " << *newSocketFD << " in thread" << std::endl;
    if (*newSocketFD < 0) {
        perror("ERROR on accept");
    }

    bool endOfCommunication = false;
    while (!endOfCommunication) {
        Action action;
        int n;
        n = read(*newSocketFD, &action, sizeof(Action));
        if (n < 0) {
            perror("Error reading from socket");
        } else if (n == 0) {
            endOfCommunication = true;
        } else {
            Reply reply;
            switch (action) {
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
                case Action::AddFriend:
                    reply = Server::getInstance().addFriend(*newSocketFD);
                    break;
                case Action::RemoveFriend:
                    reply = Server::getInstance().removeFriend(*newSocketFD);
                    break;
                case Action::GetFriendRequests:
                    reply = Server::getInstance().getFriendRequests(*newSocketFD);
                    break;
                case Action::GetHistory:
                    reply = Server::getInstance().getHistory(*newSocketFD);
                    break;
                case Action::SendFile:
                    reply = Server::getInstance().sendFile(*newSocketFD);
                    break;
                case Action::GetNewFiles:
                    reply = Server::getInstance().getNewFiles(*newSocketFD);
                    break;
                case Action::SendPublicKey:
                    reply = Server::getInstance().sendPublicKey(*newSocketFD);
                    break;
                case Action::BuildSymmetricConnection:
                    reply = Server::getInstance().buildSymmetricConnection(*newSocketFD);
                    break;
                default:
                    break;
            }

            n = write(*newSocketFD, &reply, sizeof(Reply));
            if (n < 0) {
                perror("Error writing to socket");
            }
        }
    }

    std::cout << "end socket " << *newSocketFD << " in thread" << std::endl;
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
        std::cerr << "usage " << argv[0] << " port" << std::endl;
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
        std::cout << "waiting socket " << i << std::endl;

        newSocketFD = accept(socketFD, (sockaddr *) &clientAddress, &clientAddressLength);
        std::cout << "accepted socket " << i << std::endl;
        pthread_create(&thread[i], &threadAttr, &threadMain, new int(newSocketFD));
    }

    pthread_attr_destroy(&threadAttr);

    close(socketFD);

    return 0;
}