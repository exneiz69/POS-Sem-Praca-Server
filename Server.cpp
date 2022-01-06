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

Server::Server() {
    pthread_mutex_init(&this->usersFileMutex, NULL);
    pthread_mutex_init(&this->authorizedUsersFileMutex, NULL);
    pthread_mutex_init(&this->unreadMessagesListMutex, NULL);
    pthread_mutex_init(&this->friendListFileMutex, NULL);
}

Server::~Server() {
    pthread_mutex_destroy(&this->usersFileMutex);
    pthread_mutex_destroy(&this->authorizedUsersFileMutex);
    pthread_mutex_destroy(&this->unreadMessagesListMutex);
    pthread_mutex_destroy(&this->friendListFileMutex);
}

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
            this->addNewUser(newUser);

            reply = Reply::Success;
        } else {
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }

    //*
    pthread_mutex_lock(&this->usersFileMutex);
    std::ifstream testInFile("Users.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->usersFileMutex);
    //*

    std::cout << "REPLY " << (int) reply << std::endl;

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
            perror("Error reading to socket");
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
    pthread_mutex_lock(&this->usersFileMutex);
    std::ifstream testInFile("Users.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->usersFileMutex);
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
        std::cout << "Login: " << user.login << " password: " << user.password << std::endl;

        bool isExisting;
        isExisting = this->checkRegisteredUser(user, true);

        if (isExisting) {
            this->addNewIP(this->getIP(socketFD), user.login);

            reply = Reply::Success;
        } else {
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }

    //*
    pthread_mutex_lock(&this->authorizedUsersFileMutex);
    std::ifstream testInFile("AuthorizedUsers.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->authorizedUsersFileMutex);
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
            perror("Error reading to socket");
        }

        if (reply == Reply::Agree) {
            this->deleteAuthorizedIP(this->getIP(socketFD));
        }

        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    //*
    pthread_mutex_lock(&this->authorizedUsersFileMutex);
    std::ifstream testInFile("AuthorizedUsers.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->authorizedUsersFileMutex);
    //*

    std::cout << "REPLY " << (int) reply << std::endl;

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

        userData user;
        strncpy(user.login, message.to, 24);
        bool isExisting;
        isExisting = this->checkRegisteredUser(user);

        if (isExisting) {
            messageData fullMessage;
            strncpy(fullMessage.from, currentLogin.c_str(), currentLogin.size());
            strncpy(fullMessage.to, message.to, 24);
            strncpy(fullMessage.text, message.text, 256);
            std::cout << "From: " << fullMessage.from << " to: " << fullMessage.to << " text: " << fullMessage.text
                      << std::endl;
            this->addNewMessage(fullMessage);
            reply = Reply::Success;
        } else {
            reply = Reply::Failure;
        }
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
        pthread_mutex_lock(&this->unreadMessagesListMutex);
        for (auto it = this->unreadMessages.begin(); it != this->unreadMessages.end(); ++it) {
            if (currentLogin == (*it).to) {
                newMessagesNumber++;
            }
        }
        pthread_mutex_unlock(&this->unreadMessagesListMutex);

        std::cout << "New messages number: " << newMessagesNumber << std::endl;
        n = write(socketFD, &newMessagesNumber, sizeof(int));
        if (n < 0) {
            perror("Error writing to socket");
        }

        if (newMessagesNumber != 0) {
            pthread_mutex_lock(&this->unreadMessagesListMutex);
            for (auto it = this->unreadMessages.begin(); it != this->unreadMessages.end();) {
                if (currentLogin == (*it).to) {
                    std::cout << "From: " << (*it).from << " to: " << (*it).to << " text: " << (*it).text << std::endl;
                    n = write(socketFD, &(*it), sizeof(messageData));
                    if (n < 0) {
                        perror("Error writing to socket");
                    }
                    it = this->unreadMessages.erase(it);
                } else {
                    ++it;
                }
            }
            pthread_mutex_unlock(&this->unreadMessagesListMutex);
        }

        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    return reply;
}

Reply Server::addFriend(const int socketFD) {
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

        userData user;
        n = read(socketFD, &user, sizeof(userData::login));
        if (n < 0) {
            perror("Error reading from socket");
        }
        std::cout << "Login: " << user.login << std::endl;

        bool isExisting;
        isExisting = this->checkRegisteredUser(user);
        bool isAlreadyInFriendList;
        isAlreadyInFriendList = this->checkFriend(currentLogin, user.login, true);

        if (isExisting && !isAlreadyInFriendList) {
            this->addToFriendList(currentLogin, user.login);

            reply = Reply::Success;
        } else {
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }

    //*
    pthread_mutex_lock(&this->friendListFileMutex);
    std::ifstream testInFile("FriendList.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->friendListFileMutex);
    //*

    return reply;
}

Reply Server::removeFriend(const int socketFD) {
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

        userData user;
        n = read(socketFD, &user, sizeof(userData::login));
        if (n < 0) {
            perror("Error reading from socket");
        }
        std::cout << "Login: " << user.login << std::endl;

        bool isExisting;
        isExisting = this->checkRegisteredUser(user);
        bool isFriend;
        isFriend = this->checkFriend(currentLogin, user.login, true, true);

        if (isExisting && isFriend) {
            this->deleteFromFriendList(currentLogin, user.login);

            reply = Reply::Success;
        } else {
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }

    //*
    pthread_mutex_lock(&this->friendListFileMutex);
    std::ifstream testInFile("FriendList.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->friendListFileMutex);
    //*

    return reply;
}

Reply Server::getFriendRequests(const int socketFD) {
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

        int friendRequestsNumber;
        friendRequestsNumber = this->getFriendRequestsNumber(currentLogin);

        std::cout << "Friend requests number: " << friendRequestsNumber << std::endl;
        n = write(socketFD, &friendRequestsNumber, sizeof(int));
        if (n < 0) {
            perror("Error writing to socket");
        }

        if (friendRequestsNumber != 0) {
            pthread_mutex_lock(&this->friendListFileMutex);
            std::ifstream inFile("FriendList.csv");
            std::ofstream outFile("FriendList.csv.temp");

            std::string line;
            std::string loginFrom, loginTo, isConfirmed;
            Reply reply;
            while (getline(inFile, line)) {
                std::stringstream lineStream(line);
                std::getline(lineStream, loginFrom, ',');
                std::getline(lineStream, loginTo, ',');
                std::getline(lineStream, isConfirmed, ',');

                if (currentLogin == loginTo && isConfirmed == "0") {
                    userData user;
                    strncpy(user.login, loginFrom.c_str(), 24);
                    n = write(socketFD, &user, sizeof(userData::login));
                    if (n < 0) {
                        perror("Error writing from socket");
                    }
                    std::cout << "Login: " << user.login << std::endl;

                    n = read(socketFD, &reply, sizeof(Reply));
                    if (n < 0) {
                        perror("Error reading to socket");
                    }

                    if (reply == Reply::Agree) {
                        outFile << loginFrom << ',' << loginTo << ',' << '1' << std::endl;
                    }
                } else {
                    outFile << loginFrom << ',' << loginTo << ',' << isConfirmed << std::endl;
                }
            }

            inFile.close();
            outFile.close();

            remove("FriendList.csv");
            rename("FriendList.csv.temp", "FriendList.csv");
            pthread_mutex_unlock(&this->friendListFileMutex);
        }

        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    //*
    pthread_mutex_lock(&this->friendListFileMutex);
    std::ifstream testInFile("FriendList.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->friendListFileMutex);
    //*

    return reply;
}

bool Server::checkRegisteredUser(const userData &user, const bool comparePassword) {
    pthread_mutex_lock(&this->usersFileMutex);
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
    pthread_mutex_unlock(&this->usersFileMutex);

    return isExisting;
}

bool Server::checkAuthorization(const int socketFD) {
    std::string currentIP = this->getIP(socketFD);

    pthread_mutex_lock(&this->authorizedUsersFileMutex);
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
    pthread_mutex_unlock(&this->authorizedUsersFileMutex);

    return isAlreadyAuthorized;
}

void Server::addNewUser(const userData &newUser) {
    pthread_mutex_lock(&this->usersFileMutex);
    std::ofstream outFile("Users.csv", std::ios::app);

    outFile << newUser.login << ',' << newUser.password << std::endl;
    std::cout << "Login: " << newUser.login << " password: " << newUser.password << std::endl;

    outFile.close();
    pthread_mutex_unlock(&this->usersFileMutex);
}

void Server::addNewIP(const std::string newIP, const std::string registeredLogin) {
    pthread_mutex_lock(&this->authorizedUsersFileMutex);
    std::ofstream outFile("AuthorizedUsers.csv", std::ios::app);

    outFile << newIP << ',' << registeredLogin << std::endl;
    std::cout << "IP: " << newIP << " login: " << registeredLogin << std::endl;

    outFile.close();
    pthread_mutex_unlock(&this->authorizedUsersFileMutex);
}

void Server::deleteRegisteredUser(const std::string registeredLogin) {
    pthread_mutex_lock(&this->usersFileMutex);
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
    pthread_mutex_unlock(&this->usersFileMutex);
}

void Server::deleteAuthorizedIP(const std::string authorizedIP) {
    pthread_mutex_lock(&this->authorizedUsersFileMutex);
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
    pthread_mutex_unlock(&this->authorizedUsersFileMutex);
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

    pthread_mutex_lock(&this->usersFileMutex);
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
    pthread_mutex_unlock(&this->usersFileMutex);

    return currentLogin;
}

void Server::addNewMessage(const messageData &message) {
    pthread_mutex_lock(&this->unreadMessagesListMutex);
    this->unreadMessages.push_back(message);
    pthread_mutex_unlock(&this->unreadMessagesListMutex);
}

bool Server::checkFriend(const std::string currentLogin, const std::string friendLogin, const bool bilateralCheck,
                         const bool checkConfirmation) {
    pthread_mutex_lock(&this->friendListFileMutex);
    std::ifstream inFile("FriendList.csv");

    std::string line;
    std::string loginFrom, loginTo, isConfirmed;
    bool isExisting = false;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, loginFrom, ',');
        std::getline(lineStream, loginTo, ',');
        std::getline(lineStream, isConfirmed, ',');

        if ((currentLogin == loginFrom && friendLogin == loginTo) ||
            (bilateralCheck && friendLogin == loginFrom && currentLogin == loginTo)) {
            if (checkConfirmation) {
                if (isConfirmed == "1") {
                    isExisting = true;
                }
            } else {
                isExisting = true;
            }
            break;
        }
    }
    inFile.close();
    pthread_mutex_unlock(&this->friendListFileMutex);

    return isExisting;
}

void Server::addToFriendList(const std::string currentLogin, const std::string friendLogin) {
    pthread_mutex_lock(&this->friendListFileMutex);
    std::ofstream outFile("FriendList.csv", std::ios::app);

    outFile << currentLogin << ',' << friendLogin << ',' << '0' << std::endl;
    std::cout << "Login: " << currentLogin << " friend login: " << friendLogin << std::endl;

    outFile.close();
    pthread_mutex_unlock(&this->friendListFileMutex);
}

void Server::deleteFromFriendList(const std::string currentLogin, const std::string friendLogin) {
    pthread_mutex_lock(&this->friendListFileMutex);
    std::ifstream inFile("FriendList.csv");
    std::ofstream outFile("FriendList.csv.temp");

    std::string line;
    std::string loginFrom, loginTo, isConfirmed;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, loginFrom, ',');
        std::getline(lineStream, loginTo, ',');
        std::getline(lineStream, isConfirmed, ',');

        if ((currentLogin != loginFrom || friendLogin != loginTo) && (friendLogin != loginFrom ||
            currentLogin != loginTo)) {
            outFile << loginFrom << ',' << loginTo << ',' << isConfirmed << std::endl;
        }
    }

    inFile.close();
    outFile.close();

    remove("FriendList.csv");
    rename("FriendList.csv.temp", "FriendList.csv");
    pthread_mutex_unlock(&this->friendListFileMutex);
}

int Server::getFriendRequestsNumber(const std::string login) {
    pthread_mutex_lock(&this->friendListFileMutex);
    std::ifstream inFile("FriendList.csv");

    std::string line;
    std::string loginFrom, loginTo, isConfirmed;
    int friendRequestsNumber = 0;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, loginFrom, ',');
        std::getline(lineStream, loginTo, ',');
        std::getline(lineStream, isConfirmed, ',');

        if (login == loginTo && isConfirmed == "0") {
            friendRequestsNumber++;
        }
    }

    inFile.close();
    pthread_mutex_unlock(&this->friendListFileMutex);

    return friendRequestsNumber;
}
