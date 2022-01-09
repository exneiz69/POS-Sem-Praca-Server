#include "Server.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cmath>
#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>

Server::Server() {
    this->usersFileMutex = PTHREAD_MUTEX_INITIALIZER;
    this->authorizedUsersFileMutex = PTHREAD_MUTEX_INITIALIZER;
    this->unreadMessagesListMutex = PTHREAD_MUTEX_INITIALIZER;
    this->friendListFileMutex = PTHREAD_MUTEX_INITIALIZER;
    this->historyFileMutex = PTHREAD_MUTEX_INITIALIZER;
    this->unreadFilesListMutex = PTHREAD_MUTEX_INITIALIZER;
    this->groupsFileMutex = PTHREAD_MUTEX_INITIALIZER;
}

Server::~Server() {
    pthread_mutex_destroy(&this->usersFileMutex);
    pthread_mutex_destroy(&this->authorizedUsersFileMutex);
    pthread_mutex_destroy(&this->unreadMessagesListMutex);
    pthread_mutex_destroy(&this->friendListFileMutex);
    pthread_mutex_destroy(&this->historyFileMutex);
    pthread_mutex_destroy(&this->unreadFilesListMutex);
    pthread_mutex_destroy(&this->groupsFileMutex);
}

Reply Server::registerNewUser(const int socketFD) {
    bool isAuthorized;
    isAuthorized = this->checkAuthorization(socketFD);
    Reply reply;
    if (!isAuthorized) {
        reply = Reply::Allowed;

        ssize_t n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        userData newUser;
        n = read(socketFD, &newUser, sizeof(userData));
        if (n < 0) {
            perror("Error reading from socket");
        }
        std::cout << "Login: " << newUser.login << std::endl;

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

    std::cout << "Users:" << std::endl;
    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->usersFileMutex);
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

        ssize_t n;
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

    std::cout << "Users:" << std::endl;
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

        ssize_t n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        userData user;
        n = read(socketFD, &user, sizeof(userData));
        if (n < 0) {
            perror("Error reading from socket");
        }
        std::cout << "Login: " << user.login << std::endl;

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

    std::cout << "AuthorizedUsers:" << std::endl;
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

        ssize_t n;
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

    std::cout << "AuthorizedUsers:" << std::endl;
    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->authorizedUsersFileMutex);
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

        ssize_t n;
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
        bool isGroup;
        isGroup = this->checkGroup(message.to);
        if (isExisting) {
            messageData fullMessage;
            strncpy(fullMessage.from, currentLogin.c_str(), currentLogin.size());
            strncpy(fullMessage.to, message.to, 24);
            strncpy(fullMessage.text, message.text, 256);
            std::cout << "From: " << fullMessage.from << " to: " << fullMessage.to << " text: " << fullMessage.text
                      << std::endl;
            this->addNewMessage(fullMessage);
            reply = Reply::Success;
        } else if (isGroup) {
            if (checkUserInGroup(message.to, currentLogin)) {
                messageData fullMessage;
                strncpy(fullMessage.from, currentLogin.c_str(), currentLogin.size());
                strncpy(fullMessage.to, message.to, 24);
                strncpy(fullMessage.text, message.text, 256);
                std::cout << "From: " << fullMessage.from << " to: " << fullMessage.to << " text: " << fullMessage.text
                          << std::endl;
                this->addNewMessageGroup(fullMessage, fullMessage.to, currentLogin);
                reply = Reply::Success;
            } else {
                reply = Reply::Denied;
            }
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

        ssize_t n;
        n = write(socketFD, &reply, (int) sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        int newMessagesNumber = 0;
        pthread_mutex_lock(&this->unreadMessagesListMutex);
        for (auto &unreadMessage: this->unreadMessages) {
            if (currentLogin == unreadMessage.to) {
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
    int privateKey;
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        ssize_t n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        userData user;
        n = read(socketFD, &user, sizeof(userData::login));
        if (n < 0) {
            perror("Error reading from socket");
        }
        std::cout << "Friend login: " << user.login << std::endl;

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

    std::cout << "FriendList:" << std::endl;
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

        ssize_t n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        userData user;
        n = read(socketFD, &user, sizeof(userData::login));
        if (n < 0) {
            perror("Error reading from socket");
        }
        std::cout << "Friend login: " << user.login << std::endl;

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

    std::cout << "FriendList:" << std::endl;
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

        ssize_t n;
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
                    std::cout << "Friend login: " << user.login << std::endl;

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

    std::cout << "FriendList:" << std::endl;
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
    std::string login;
    std::string password;
    bool isExisting = false;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, login, ',');
        std::getline(lineStream, password, ',');

        if (user.login == login) {
            if (comparePassword) {
                if (encryptPassword(user.password) == password) {
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

    outFile << newUser.login << ',' << encryptPassword(newUser.password) << std::endl;
    std::cout << "Login: " << newUser.login << std::endl;

    outFile.close();
    pthread_mutex_unlock(&this->usersFileMutex);
}

void Server::addNewIP(const std::string& newIP, const std::string& registeredLogin) {
    pthread_mutex_lock(&this->authorizedUsersFileMutex);
    std::ofstream outFile("AuthorizedUsers.csv", std::ios::app);

    outFile << newIP << ',' << registeredLogin << std::endl;
    std::cout << "IP: " << newIP << " login: " << registeredLogin << std::endl;

    outFile.close();
    pthread_mutex_unlock(&this->authorizedUsersFileMutex);
}

void Server::deleteRegisteredUser(const std::string& registeredLogin) {
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

void Server::deleteAuthorizedIP(const std::string& authorizedIP) {
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
    sockaddr_in currentAddress = {0};
    socklen_t currentAddressLength = sizeof(currentAddress);
    getpeername(socketFD, (sockaddr *) &currentAddress, &currentAddressLength);
    char currentIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(currentAddress.sin_addr), currentIP, INET_ADDRSTRLEN);
    return {currentIP};
}

std::string Server::getLoginByAuthorization(const int socketFD) {
    std::string currentIP = this->getIP(socketFD);

    pthread_mutex_lock(&this->usersFileMutex);
    std::ifstream inFile("AuthorizedUsers.csv");

    std::string line;
    std::string ip, login;
    std::string currentLogin;
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

    // zapisat do historie
    pthread_mutex_lock(&this->historyFileMutex);

    std::ofstream outFile("History.csv", std::ios_base::app);
    if (outFile.is_open()) {
        outFile << message.from << ',' << message.to << ',' << message.text << std::endl;
    }
    outFile.close();

    pthread_mutex_unlock(&this->historyFileMutex);
}

bool Server::checkFriend(const std::string& currentLogin, const std::string& friendLogin, const bool bilateralCheck,
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

void Server::addToFriendList(const std::string& currentLogin, const std::string& friendLogin) {
    pthread_mutex_lock(&this->friendListFileMutex);
    std::ofstream outFile("FriendList.csv", std::ios::app);

    outFile << currentLogin << ',' << friendLogin << ',' << '0' << std::endl;
    std::cout << "Login: " << currentLogin << " add friend: " << friendLogin << std::endl;

    outFile.close();
    pthread_mutex_unlock(&this->friendListFileMutex);
}

void Server::deleteFromFriendList(const std::string& currentLogin, const std::string& friendLogin) {
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

int Server::getFriendRequestsNumber(const std::string& login) {
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

Reply Server::getHistory(const int socketFD) {
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    isAuthorized = !currentLogin.empty();
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        ssize_t n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        int *historyIndexes = getHistoryIndexes(currentLogin);

        std::cout << "History indexes number: " << historyIndexes[0] << std::endl;
        n = write(socketFD, &historyIndexes[0], sizeof(int));
        if (n < 0) {
            perror("Error writing to socket");
        }

        if (historyIndexes[0] != 0) {
            pthread_mutex_lock(&this->historyFileMutex);
            std::ifstream inFile("History.csv");

            std::string line;
            std::string from, to, text;

            int lineNumber = 0; // kde sa nachadzame
            int historyIndexIndex = 1; // index v historyIndexes  [a, b, c, ...]
            int lookingForLineNumber = historyIndexes[historyIndexIndex];
            int howManyLinesImLookingFor = historyIndexes[0];

            while (getline(inFile, line) && historyIndexIndex <= howManyLinesImLookingFor) {

                if (lineNumber == lookingForLineNumber) {
                    std::stringstream lineStream(line);
                    std::getline(lineStream, from, ',');
                    std::getline(lineStream, to, ',');
                    std::getline(lineStream, text, ',');

                    messageData message;
                    strncpy(message.from, from.c_str(), 24);
                    strncpy(message.to, to.c_str(), 24);
                    strncpy(message.text, text.c_str(), 256);

                    n = write(socketFD, &message, sizeof(messageData));
                    if (n < 0) {
                        perror("Error writing from socket");
                    }

                    if (historyIndexIndex != howManyLinesImLookingFor) {
                        historyIndexIndex++;
                        lookingForLineNumber = historyIndexes[historyIndexIndex];
                    } else {
                        historyIndexIndex++;
                    }
                }
                lineNumber++;
            }
            inFile.close();
            pthread_mutex_unlock(&this->historyFileMutex);
        }
        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    //*
    pthread_mutex_lock(&this->historyFileMutex);
    std::ifstream testInFile("History.csv");

    std::cout << "History:" << std::endl;
    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->historyFileMutex);
    //*

    return reply;
}

int *Server::getHistoryIndexes(const std::string& login) {
    pthread_mutex_lock(&this->historyFileMutex);
    std::ifstream inFile("History.csv");

    int *numberedLines = new int[1024];
    int numberedLinesLen = 0;
    int lineIndex = 0;

    std::string line;
    std::string from, to, text;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, from, ',');
        std::getline(lineStream, to, ',');
        std::getline(lineStream, text, ',');

        if (from == login || to == login) {
            numberedLines[numberedLinesLen++] = lineIndex;
        }

        lineIndex++;
    }

    inFile.close();
    pthread_mutex_unlock(&this->historyFileMutex);

    int *ret = new int[1 + numberedLinesLen];
    ret[0] = numberedLinesLen;
    for (int i = 0; i < numberedLinesLen; i++) {
        ret[i + 1] = numberedLines[i];
    }
    delete[] numberedLines;
    numberedLines = nullptr;

    return ret;
}

std::string Server::encryptPassword(const std::string& password) {
    std::string unencryptedPassword = "Dano";
    std::string encryptedPassword;
    unencryptedPassword += password;
    unencryptedPassword += "Drevo";
    int messageLength = (int)unencryptedPassword.length();
    char temp;

    for (int j = 0; j < 80; ++j) {
        temp = unencryptedPassword[0];
        for (int i = 0; i < messageLength - 1; ++i) {
            unencryptedPassword[i] = unencryptedPassword[i + 1];
        }
        unencryptedPassword[messageLength - 1] = temp;
    }

    for (int i = 0; i < messageLength; ++i) {
        unencryptedPassword[i] = (char)(unencryptedPassword[i] % 74);
        unencryptedPassword[i] += (char)128;
    }
    for (int i = messageLength - 1; i >= 0; --i) {
        encryptedPassword.push_back(unencryptedPassword[i]);
    }
    return encryptedPassword;
}

Reply Server::sendFile(const int socketFD) {
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    isAuthorized = !currentLogin.empty();
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        ssize_t n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        fileReducedData file;
        n = read(socketFD, &file, sizeof(fileReducedData));
        if (n < 0) {
            perror("Error reading from socket");
        }

        userData user;
        strncpy(user.login, file.to, 24);
        bool isExisting;
        isExisting = this->checkRegisteredUser(user);
        bool isGroup;
        isGroup = this->checkGroup(file.to);

        if (isExisting) {
            fileData fd;
            strncpy(fd.from, currentLogin.c_str(), currentLogin.size());
            strncpy(fd.to, file.to, sizeof(fileData::to));
            strncpy(fd.name, file.name, sizeof(fileData::name));
            strncpy(fd.data, file.data, sizeof(fileData::data));
            std::cout << "From: " << fd.from << " to: " << fd.to << " file name: " << fd.name << std::endl;
            this->addNewFile(fd);
            reply = Reply::Success;
        } else if (isGroup) {
            if (checkUserInGroup(file.to, currentLogin)) {
                fileData fd;
                strncpy(fd.from, currentLogin.c_str(), currentLogin.size());
                strncpy(fd.to, file.to, 24);
                strncpy(fd.data, file.data, sizeof(fileData::data));
                strncpy(fd.name, file.name, sizeof(fileData::name));
                this->addNewFileGroup(fd, fd.to, currentLogin);
                reply = Reply::Success;
            } else {
                reply = Reply::Denied;
            }
        } else {
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }

    return reply;
}

Reply Server::getNewFiles(const int socketFD) {
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    isAuthorized = !currentLogin.empty();
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        ssize_t n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        int newFilesNumber = 0;
        pthread_mutex_lock(&this->unreadFilesListMutex);
        for (auto & unreadFile : this->unreadFiles) {
            if (currentLogin == unreadFile.to) {
                newFilesNumber++;
            }
        }
        pthread_mutex_unlock(&this->unreadFilesListMutex);

        std::cout << "New files number: " << newFilesNumber << std::endl;
        n = write(socketFD, &newFilesNumber, sizeof(int));
        if (n < 0) {
            perror("Error writing to socket");
        }

        if (newFilesNumber != 0) {
            pthread_mutex_lock(&this->unreadFilesListMutex);

            for (auto it = this->unreadFiles.begin(); it != this->unreadFiles.end();) {
                if (currentLogin == (*it).to) {
                    std::cout << "From: " << (*it).from << " to: " << (*it).to << " file name: " << (*it).name
                              << std::endl;
                    n = write(socketFD, &(*it), sizeof(fileData));
                    if (n < 0) {
                        perror("Error writing to socket");
                    }
                    it = this->unreadFiles.erase(it);
                } else {
                    ++it;
                }
            }

            pthread_mutex_unlock(&this->unreadFilesListMutex);
        }

        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    return reply;
}

void Server::addNewFile(const fileData &file) {
    pthread_mutex_lock(&this->unreadFilesListMutex);
    this->unreadFiles.push_back(file);
    pthread_mutex_unlock(&this->unreadFilesListMutex);
}

void Server::addNewFileGroup(const fileData &file, const std::string& group, const std::string& login) {
    pthread_mutex_lock(&this->unreadFilesListMutex);
    std::list<std::string> recipients;
    recipients = getGroupNames(group, login);

    for (auto & recipient : recipients) {
        strcpy((char *) file.from, group.c_str()); //TOTO URCUJE, CI ODOSIELATEL JE MENOVITY ALEBO SKUPINA
        strcpy((char *) file.to, recipient.c_str());
        this->unreadFiles.push_back(file);
        std::cout << "From: " << file.from << " to: " << file.to << " file name: " << file.name << std::endl;
    }

    pthread_mutex_unlock(&this->unreadFilesListMutex);
}

Reply Server::createGroup(const int socketFD) {
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    isAuthorized = !currentLogin.empty();
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        ssize_t n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        groupData gd;
        n = read(socketFD, &gd, sizeof(groupData));
        if (n < 0) {
            perror("Error reading from socket");
        }

        bool isExisting = false;
        isExisting = checkGroup(gd.name);

        if (!isExisting) {
            this->addNewGroup(gd.name);
            reply = Reply::Success;
        } else {
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }

    return reply;
}

bool Server::checkGroup(const std::string& groupName) {
    pthread_mutex_lock(&this->groupsFileMutex);
    std::ifstream inFile("Groups.csv");

    std::string line;
    std::string name;
    bool isExisting = false;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, name, ',');

        if (name == groupName) {
            isExisting = true;
            break;
        }
    }
    inFile.close();
    pthread_mutex_unlock(&this->groupsFileMutex);

    return isExisting;
}

void Server::addNewGroup(const std::string& groupName) {
    pthread_mutex_lock(&this->groupsFileMutex);
    std::ofstream outFile("Groups.csv", std::ios::app);

    outFile << groupName << std::endl;
    std::cout << "Group name: " << groupName << " added" << std::endl;

    outFile.close();
    pthread_mutex_unlock(&this->groupsFileMutex);

    //*
    pthread_mutex_lock(&this->groupsFileMutex);
    std::ifstream testInFile("Groups.csv");

    std::cout << "Group:" << std::endl;
    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }
    testInFile.close();
    pthread_mutex_unlock(&this->groupsFileMutex);
    //*
}

Reply Server::addUserToGroup(const int socketFD) {
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    isAuthorized = !currentLogin.empty();
    Reply reply;
    if (isAuthorized) {
        reply = Reply::Allowed;

        ssize_t n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }

        groupData gd;
        n = read(socketFD, &gd, sizeof(groupData));
        if (n < 0) {
            perror("Error reading from socket");
        }

        bool isExisting = false;
        isExisting = checkGroup(gd.name);

        if (isExisting) {
            pthread_mutex_lock(&this->groupsFileMutex);
            std::ifstream inFile("Groups.csv");
            std::ofstream outFile("Groups.csv.temp");

            std::string line;
            std::string name;
            bool alreadyAdded = false;
            reply = Reply::Failure;
            while (getline(inFile, line)) {
                std::stringstream lineStream(line);
                std::getline(lineStream, name, ',');

                if (!alreadyAdded && name == std::string(gd.name)) {
                    if (!checkUserInGroup(line, currentLogin)) {
                        outFile << line << ',' << currentLogin << std::endl;
                        reply = Reply::Success;
                    }
                    alreadyAdded = true;
                } else {
                    outFile << line << std::endl;
                }
            }

            inFile.close();
            outFile.close();

            remove("Groups.csv");
            rename("Groups.csv.temp", "Groups.csv");
            pthread_mutex_unlock(&this->groupsFileMutex);
        } else {
            reply = Reply::Failure;
        }

    } else {
        reply = Reply::Denied;
    }

    //*
    pthread_mutex_lock(&this->groupsFileMutex);
    std::ifstream testInFile("Groups.csv");

    std::cout << "Group:" << std::endl;
    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->groupsFileMutex);
    //*

    return reply;
}

bool Server::checkUserInGroup(const std::string& group, const std::string& login) {
    bool isExisting = false;
    bool end = false;

    pthread_mutex_lock(&this->groupsFileMutex);
    std::ifstream inFile("Groups.csv");

    std::string line;
    std::string groupName;
    std::string userName;
    while (getline(inFile, line)) {
        if (end)
            break;
        std::stringstream lineStream(line);
        std::getline(lineStream, groupName, ',');
        if (groupName == group) {
            while (std::getline(lineStream, userName, ',')) {
                if (userName == login) {
                    isExisting = true;
                    end = true;
                    break;
                }
            }
        }
    }

    inFile.close();
    pthread_mutex_unlock(&this->groupsFileMutex);

    return isExisting;
}

void Server::addNewMessageGroup(messageData fullMessage, const std::string& group, const std::string& login) {
    pthread_mutex_lock(&this->unreadMessagesListMutex);
    std::list<std::string> recipients;
    recipients = getGroupNames(group, login);

    for (auto & recipient : recipients) {
        strcpy(fullMessage.from, group.c_str()); //TOTO URCUJE, CI ODOSIELATEL JE MENOVITY ALEBO SKUPINA
        strcpy(fullMessage.to, recipient.c_str());
        this->unreadMessages.push_back(fullMessage);
        std::cout << "From: " << fullMessage.from << " to: " << fullMessage.to << " text: " << fullMessage.text
                  << std::endl;
    }

    pthread_mutex_unlock(&this->unreadMessagesListMutex);
}

std::list<std::string> Server::getGroupNames(const std::string& group, const std::string& login) {
    std::list<std::string> groupNames;

    pthread_mutex_lock(&this->groupsFileMutex);
    std::ifstream inFile("Groups.csv");

    std::string line;
    std::string groupName;
    std::string userName;
    while (getline(inFile, line)) {
        std::stringstream lineStream(line);
        std::getline(lineStream, groupName, ',');
        if (groupName == group) {
            while (std::getline(lineStream, userName, ',')) {
                if (userName != login) {
                    groupNames.push_back(userName);
                }
            }
        }
    }

    inFile.close();
    pthread_mutex_unlock(&this->groupsFileMutex);

    //*
    pthread_mutex_lock(&this->groupsFileMutex);
    std::ifstream testInFile("Groups.csv");

    std::cout << "Group:" << std::endl;
    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->groupsFileMutex);
    //*

    return groupNames;
}