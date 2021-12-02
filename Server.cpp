#include "Server.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>

Reply Server::registerNewUser(const int socketFD) {
    bool isAuthorized;
    isAuthorized = this->checkAuthorization(socketFD);
    Reply reply;
    if (!isAuthorized) {
        reply = Reply::Allowed;

        int n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        userData newUser;
        n = read(socketFD, &newUser, sizeof(userData));
        if (n < 0) {
            perror("Error reading from socket");
        }

        bool isAlreadyExisting;
        isAlreadyExisting = this->checkRegisteredUser(newUser);

        if (!isAlreadyExisting) {
            std::ofstream outFile("Users.csv", std::ios::app);

            outFile << newUser.login << ',' << newUser.password << std::endl;
            printf("Login: %s password: %s\n", newUser.login, newUser.password);

            outFile.close();

            reply = Reply::Success;
        } else {
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }

    //*
    std::ifstream testInFile("Users.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    //*

    return reply;
}

Reply Server::unregisterUser(const int socketFD) {
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    isAuthorized = !currentLogin.empty();
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        int n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        n = read(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        if (reply == Reply::Agree) {
            this->deleteAuthorizedIP(this->getIP(socketFD));
            this->deleteRegisteredUser(currentLogin);
        }

        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    //*
    std::ifstream testInFile("Users.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    //*

    return reply;
}

Reply Server::authorizeUser(const int socketFD) {
    bool isAlreadyAuthorized;
    isAlreadyAuthorized = this->checkAuthorization(socketFD);
    Reply reply;
    if (!isAlreadyAuthorized) {
        reply = Reply::Allowed;

        int n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        userData user;
        n = read(socketFD, &user, sizeof(userData));
        if (n < 0) {
            perror("Error reading from socket");
        }
        printf("Login: %s password: %s\n", user.login, user.password);

        bool isExisting;
        isExisting = this->checkRegisteredUser(user, true);

        if (isExisting) {
            std::ofstream outFile("AuthorizedUsers.csv", std::ios::app);

            std::string currentIP = this->getIP(socketFD);
            outFile << currentIP << ',' << user.login << std::endl;
            printf("IP: %s login: %s\n", currentIP.c_str(), user.login);

            outFile.close();

            reply = Reply::Success;
        } else {
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }

    //*
    std::ifstream testInFile("AuthorizedUsers.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    //*

    return reply;
}

Reply Server::deauthorizeUser(const int socketFD) {
    bool isAuthorized;
    isAuthorized = this->checkAuthorization(socketFD);
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        int n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        n = read(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        if (reply == Reply::Agree) {
            this->deleteAuthorizedIP(this->getIP(socketFD));
        }

        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    //*
    std::ifstream testInFile("AuthorizedUsers.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    //*

    return reply;
}

Reply Server::getMessage(const int socketFD) {
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    isAuthorized = !currentLogin.empty();
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        int n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        messageReducedData message;
        n = read(socketFD, &message, sizeof(messageReducedData));
        if (n < 0) {
            perror("Error reading from socket");
        }

        messageData fullMessage;
        strncpy(fullMessage.from, currentLogin.c_str(), currentLogin.size());
        strncpy(fullMessage.to, message.to, 24);
        strncpy(fullMessage.text, message.text, 256);
        printf("From: %s to: %s text: %s\n", fullMessage.from, fullMessage.to, fullMessage.text);
        this->addNewMessage(fullMessage);
        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    return reply;
}

Reply Server::sendNewMessages(const int socketFD) {
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    isAuthorized = !currentLogin.empty();
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        int n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        int newMessagesNumber = 0;
        for (auto it = this->unreadMessages.begin(); it != this->unreadMessages.end(); ++it) {
            if (currentLogin == (*it).to) {
                newMessagesNumber++;
            }
        }
        printf("New messages number: %d\n", newMessagesNumber);

        n = write(socketFD, &newMessagesNumber, sizeof(int));
        if (n < 0) {
            perror("Error writing to socket");
        }

        if (newMessagesNumber != 0) {
            for (auto it = this->unreadMessages.begin(); it != this->unreadMessages.end();) {
                if (currentLogin == (*it).to) {
                    printf("From: %s to: %s text: %s\n", (*it).from, (*it).to, (*it).text);
                    n = write(socketFD, &(*it), sizeof(messageData));
                    if (n < 0) {
                        perror("Error writing to socket");
                    }
                    it = this->unreadMessages.erase(it);
                } else {
                    ++it;
                }
            }
        }

        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    return reply;
}

bool Server::checkRegisteredUser(const userData &user, const bool comparePassword) {
    std::ifstream inFile("Users.csv");

    std::string line;
    std::string login, password;
    bool isExisting = false;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, login, ',');
        std::getline(lineStream, password, ',');

        if (user.login == login) {
            if (comparePassword) {
                if (user.password == password) {
                    isExisting = true;
                }
            } else {
                isExisting = true;
            }
            break;
        }
    }

    inFile.close();

    return isExisting;
}

bool Server::checkAuthorization(const int socketFD) {
    std::string currentIP = this->getIP(socketFD);
    std::ifstream inFile("AuthorizedUsers.csv");

    std::string line;
    std::string ip;
    bool isAlreadyAuthorized = false;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, ip, ',');

        if (currentIP == ip) {
            isAlreadyAuthorized = true;
            break;
        }
    }

    inFile.close();

    return isAlreadyAuthorized;
}

void Server::deleteRegisteredUser(const std::string registeredLogin) {
    std::ifstream inFile("Users.csv");
    std::ofstream outFile("Users.csv.temp");

    std::string line;
    std::string login, password;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, login, ',');
        std::getline(lineStream, password, ',');

        if (registeredLogin != login) {
            outFile << login << ',' << password << std::endl;
        }
    }

    inFile.close();
    outFile.close();

    remove("Users.csv");
    rename("Users.csv.temp", "Users.csv");
}

void Server::deleteAuthorizedIP(const std::string authorizedIP) {
    std::ifstream inFile("AuthorizedUsers.csv");
    std::ofstream outFile("AuthorizedUsers.csv.temp");

    std::string line;
    std::string ip, login;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, ip, ',');
        std::getline(lineStream, login, ',');

        if (authorizedIP != ip) {
            outFile << ip << ',' << login << std::endl;
        }
    }

    inFile.close();
    outFile.close();

    remove("AuthorizedUsers.csv");
    rename("AuthorizedUsers.csv.temp", "AuthorizedUsers.csv");
}

std::string Server::getIP(const int socketFD) {
    struct sockaddr_in currentAddress;
    socklen_t currentAddressLength = sizeof(currentAddress);
    getpeername(socketFD, (sockaddr *) &currentAddress, &currentAddressLength);
    char currentIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(currentAddress.sin_addr), currentIP, INET_ADDRSTRLEN);
    return std::string(currentIP);
}

std::string Server::getLoginByAuthorization(const int socketFD) {
    std::string currentIP = this->getIP(socketFD);
    std::ifstream inFile("AuthorizedUsers.csv");

    std::string line;
    std::string ip, login;
    std::string currentLogin = "";
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, ip, ',');
        std::getline(lineStream, login, ',');

        if (currentIP == ip) {
            currentLogin = login;
            break;
        }
    }

    inFile.close();

    return currentLogin;
}

void Server::addNewMessage(const messageData &message) {
    this->unreadMessages.push_back(message);
}