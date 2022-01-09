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
#include <stdlib.h>


Server::Server() {
    pthread_mutex_init(&this->usersFileMutex, NULL);
    pthread_mutex_init(&this->authorizedUsersFileMutex, NULL);
    pthread_mutex_init(&this->unreadMessagesListMutex, NULL);
    pthread_mutex_init(&this->friendListFileMutex, NULL);
    pthread_mutex_init(&this->historyMutex, NULL);
    pthread_mutex_init(&this->unreadFilesListMutex, NULL);
}

Server::~Server() {
    pthread_mutex_destroy(&this->usersFileMutex);
    pthread_mutex_destroy(&this->authorizedUsersFileMutex);
    pthread_mutex_destroy(&this->unreadMessagesListMutex);
    pthread_mutex_destroy(&this->friendListFileMutex);
    pthread_mutex_destroy(&this->historyMutex);
    pthread_mutex_destroy(&this->unreadFilesListMutex);
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
        std::cout << "Login: " << user.login << " password: " << encryptPassword(user.password)  <<std::endl;

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
            this->privateKeyMap.erase(getLoginByAuthorization(socketFD));
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
    int privateKey;
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
    std::cout << "Login: " << newUser.login << " password: " << encryptPassword(newUser.password) << std::endl;

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

    // zapisat do historie
    pthread_mutex_lock(&this->historyMutex);

    std::ofstream outFile("History.csv", std::ios_base::app);
    if (outFile.is_open()) {
        outFile << message.from << ',' << message.to << ',' << message.text << std::endl;
    }
    outFile.close();

    pthread_mutex_unlock(&this->historyMutex);
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

    outFile << currentLogin << ',' << friendLogin << ','<< "0" << std::endl;
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

Reply Server::getHistory(const int socketFD) {

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

        int* historyIndexes = getHistoryIndexes(currentLogin);

        std::cout << "History indexes number: " << historyIndexes[0] << std::endl;
        n = write(socketFD, &historyIndexes[0], sizeof(int));
        if (n < 0) {
            perror("Error writing to socket");
        }

        if (historyIndexes[0] != 0) {
            pthread_mutex_lock(&this->historyMutex);
            std::ifstream inFile("History.csv");

            std::string line;
            std::string from, to, text;
            Reply reply;

            int lineNumber = 0; // kde sa nachadzame
            int historyIndexIndex = 1; // index v historyIndexes  [a, b, c, ...]
            int lookingForLineNumber = historyIndexes[historyIndexIndex];
            int howManyLinesImLookingFor = historyIndexes[0];

            while (getline(inFile, line) && historyIndexIndex <= howManyLinesImLookingFor) {

                if (lineNumber == lookingForLineNumber)
                {
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
            delete[] historyIndexes;
            historyIndexes = nullptr;
            pthread_mutex_unlock(&this->historyMutex);
        }
        reply = Reply::Success;
    } else {
        reply = Reply::Denied;
    }

    //*
    pthread_mutex_lock(&this->historyMutex);
    std::ifstream testInFile("History.csv");

    std::string testLine;
    while (getline(testInFile, testLine)) {
        std::cout << "* " << testLine << std::endl;
    }

    testInFile.close();
    pthread_mutex_unlock(&this->historyMutex);
    //*

    return reply;
}

int* Server::getHistoryIndexes(const std::string login) {
    pthread_mutex_lock(&this->historyMutex);
    std::ifstream inFile("History.csv");

    int* numberedLines = new int[1024];
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
    pthread_mutex_unlock(&this->historyMutex);

    int* ret = new int[1+numberedLinesLen];
    ret[0] = numberedLinesLen;
    for (int i = 0; i < numberedLinesLen; i++) {
        ret[i+1] = numberedLines[i];
    }
    delete[] numberedLines;
    numberedLines = nullptr;

    std::cout<<"*i: ";
    for (int i = 0; i < ret[0]+1; ++i) {
        std::cout<<ret[i]<<" ";
    }

    std::cout<<std::endl;
    return ret;
}
//=======
//
// *  Pre Easy testovanie je toto.
//std::string Server::encryptPassword(const std::string password) {
//    return password;
//}
//*/
//
//
// *  Toto je basic encrypt vycucany z prsta

std::string Server::encryptPassword(const std::string password){
    std::string unencryptedPassword = "Dano";
    std::string encryptedPassword;
    unencryptedPassword += password;
    unencryptedPassword  += "Drevo";
    int messageLength = unencryptedPassword.length();
    char temp;

    for (int j = 0; j < 80; ++j) {
        temp = unencryptedPassword[0];
        for (int i = 0; i < messageLength-1; ++i) {
            unencryptedPassword[i] = unencryptedPassword[i+1];
        }
        unencryptedPassword[messageLength - 1] = temp;
    }

    for (int i = 0; i < messageLength; ++i) {
        unencryptedPassword[i] = unencryptedPassword[i] % 74;
        unencryptedPassword[i] += 128;
    }
    for (int i = messageLength-1; i >= 0; --i) {
        encryptedPassword.push_back(unencryptedPassword[i]);
    }
    return encryptedPassword;
}

Reply Server::sendFile(const int socketFD) {
    std::cout<<"in send file method"<<std::endl;
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

        fileReducedData file;
        n = read(socketFD, &file, sizeof(fileReducedData));
        if (n < 0) {
            perror("Error reading from socket");
        }

        userData user;
        strncpy(user.login, file.to, 24);
        bool isExisting;
        isExisting = this->checkRegisteredUser(user);

        if (isExisting) {
            fileData fd;
            strncpy(fd.from, currentLogin.c_str(), currentLogin.size());
            strncpy(fd.to, file.to, sizeof(fileData::to));
            strncpy(fd.name, file.name, sizeof(fileData::name));
            strncpy(fd.data, file.data, sizeof(fileData::data));
            std::cout << "From: " << fd.from << " to: " << fd.to << " file: " << fd.name << std::endl;
            this->addNewFile(fd);
            std::cout<<"yes"<<std::endl;
            reply = Reply::Success;
        } else {
            std::cout<<"nooo"<<std::endl;
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }
    return reply;
}

Reply Server::getNewFiles(const int socketFD) {
    std::cout<<"in get new file method"<<std::endl;
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

        int newFilesNumber = 0;
        pthread_mutex_lock(&this->unreadFilesListMutex);
        for (auto it = this->unreadFiles.begin(); it != this->unreadFiles.end(); ++it) {
            if (currentLogin == (*it).to) {
                newFilesNumber++;
            }
        }
        pthread_mutex_unlock(&this->unreadFilesListMutex);

        std::cout << "New messages number: " << newFilesNumber << std::endl;
        n = write(socketFD, &newFilesNumber, sizeof(int));
        if (n < 0) {
            perror("Error writing to socket");
        }

        if (newFilesNumber != 0) {
            pthread_mutex_lock(&this->unreadFilesListMutex);

            for (auto it = this->unreadFiles.begin(); it != this->unreadFiles.end();) {
                if (currentLogin == (*it).to) {
                    std::cout << "From: " << (*it).from << " to: " << (*it).to << " filename: " << (*it).name << std::endl;
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


// * Sha-Vycuc encryption NWP.
//std::string Server::encryptPassword(const std::string password){
//    std::string unencryptedPassword = password;
//    std::string encryptedPassword;
//    int ft;
//    int kt;
//    int temp;
//
//    //Padding
//    int messageLength = sizeof(unencryptedPassword);
//    unencryptedPassword += 0x80;
//    unencryptedPassword += 0x200;
//    unencryptedPassword = unencryptedPassword % 0x200;
//    int padding = (32 - messageLength);
//    std::bitset<32> message;
//    std::bitset message = std::bitset<32>(unencryptedPassword);
//
//    message<<=1;
//    message&=0x01;
//    for (int i = 0; i < padding-1; ++i) {
//        message<<=1;
//    }
//    int w[80];
//    for (int i = 0; i < 16; ++i) {
//        std::bitset<32>(message)>>w[i];
//    }
//
//    //Compresia
//    int h[5] = {0x19283764,0x1DCBEF69,0x360A9C26,0x420B4E2A,0x6A2C64DF};
//    // h0 = 0x19283764 = a0
//    // h1 = 0x1DCBEF69 = b0
//    // h2 = 0x360A9C26 = c0
//    // h3 = 0x420B4E2A = d0
//    // h4 = 0x6A2C64DF = e0
//
//    int a = h[0];
//    int b = h[1];
//    int c = h[2];
//    int d = h[3];
//    int e = h[4];
//
//    // Padding w[i] zo 16 na 80
//    for (int i = 16; i < 80; ++i) {
//        w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
//        // Leftrotate 1
//        w[i] = temp;
//        for (int j = 0; j < i; ++j) {
//            w[j+1] = w[j];
//        }
//        w[0] = temp;
//    }
//
//    for (int i = 0; i < 80; ++i) {
//        if (0 <= i && i <= 19) {        // Prva faza
//            ft = (b and c) or ((not b) and d);
//            kt = 0x5A827999;
//        }
//        else if (20 <= i && i <= 39) {  // Druha faza
//            ft = b xor c xor d;
//            kt = 0x6ED9EBA1;
//        }
//        else if (40 <= i && i <= 59) {  // Tretia faza
//            ft = (b and c) or (b and d) or (c and d);
//            kt = 0x8F1BBCDC;
//        }
//        else if (60 <= i && i <= 79) {  // Stvrta faza
//            ft = b xor c xor d;
//            kt = 0xCA62C1D6;
//        }
//
//        temp = (a*2^5) + ft + e + ft + w[i];
//        e = d;
//        d = c;
//        c = b;
//        b = a;
//        a = temp;
//
//        h[0] = h[0] + a;
//        h[1] = h[1] + b;
//        h[2] = h[2] + c;
//        h[3] = h[3] + d;
//        h[4] = h[4] + e;
//    }
//    std::stringstream ss;
//    ss << ((h[0]*2^128) + (h[1]*2^96) + (h[2]*2^64) + (h[3]*2^32) + h[4]);
//    ss >> encryptedPassword;
//    return encryptedPassword;
//}
//*/
//>>>>>>> origin/master


Reply Server::sendPublicKey(const int socketFD) {
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    isAuthorized = !currentLogin.empty();
    Reply reply;
    int n;
    if (isAuthorized) {
        reply = Reply::Allowed;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error reading from socket");
        }
        long long PublicP = this->getP();
        n = write(socketFD, &PublicP, sizeof(long long));
        if (n < 0) {
            perror("Error writing to socket");
        }

        n = read(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error reading from socket");
        }
        if (reply == Reply::Agree){
            long long PublicG = this->getG();
            n = write(socketFD, &PublicG, sizeof(long long));
            if (n < 0) {
                perror("Error writing to socket");
            }
            reply =Reply::Success;
        }
        else {
            reply = Reply::Failure;
        }
    } else {
        reply = Reply::Denied;
    }
    return reply;
}

Reply Server::buildSymmetricConnection(const int socketFD){
    std::string currentLogin;
    currentLogin = this->getLoginByAuthorization(socketFD);
    bool isAuthorized;
    Reply reply;
//    std::cout << " Zpusteny BSC pred autorizaciou" << std::endl;
    isAuthorized = !currentLogin.empty();
    if (isAuthorized) {
//        std::cout << " Zpusteny BSC po autorizacii" << std::endl;
        long long privateKeyBase = primeNumberGenerator();
        long long privateKeyComponentClient;
        long long privateKeyComponentServer;
        privateKeyComponentServer = diffieHelmanStepOne(privateKeyBase);
        reply = Reply::Allowed;
        int n;
        n = write(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }
//        std::cout << "Idem od klienta" << std::endl;
        n = read(socketFD, &privateKeyComponentClient, sizeof(long long));
        if (n < 0) {
            perror("Error reading from socket");
        }

//        std::cout << "Z klienta prislo " << privateKeyComponentClient << std::endl;

        n = read(socketFD, &reply, sizeof(Reply));
        if (n < 0) {
            perror("Error writing to socket");
        }
        if (reply == Reply::Agree) {

//            std::cout << "Idem do klienta " << std::endl;
            n = write(socketFD, &privateKeyComponentServer, sizeof(long long));
            if (n < 0) {
                perror("Error reading from socket");
            }
//            std::cout << "Do klienta odislo  " << privateKeyComponentServer << std::endl;
            long long tempKey = diffieHelmanStepTwo(privateKeyComponentClient, privateKeyBase);
            this->privateKeyMap[getLoginByAuthorization(socketFD)] = tempKey;
//            std::cout << "Success, Private key je vytvoreny. private key = " << tempKey << std::endl;
            reply = Reply::Success;
        } else {
            reply = Reply::Failure;
        }
    }
    else {
        reply = Reply::Denied;
    }
    return reply;
}

long long Server::diffieHelmanStepOne(long long Prime) {
    long long s = Prime;
    long long g = this->getG();
    long long p = this->getP();
    long long temp = ((g^s) % p);
//    std::cout << " Diffie 1 = " << temp << std::endl;
    return temp;
}

long long Server::diffieHelmanStepTwo(long long privateKeyComponentClient, long long privateKeyBase) {
    long long g = this->getG();
    long long p = this->getP();
    long long temp = ((privateKeyComponentClient)^privateKeyBase) % p;
//    std::cout << " Diffie 2 = " << temp << std::endl;
    return temp;
}

long long Server::getP(){
    long long temp = this->P;
    return temp;
}

long long Server::getG(){
    long long temp = this->G;
    return temp;
}

long long Server::primeNumberGenerator() {
    long long randomBeginning = ((rand()%20000)+ 20000) - (rand()%10000);
    long long primeNum = randomBeginning;
    bool isPrime = false;
//    std::cout << "Started searching for a sufficient prime, beginning is " << randomBeginning << std::endl;
    while (isPrime == false) {
        isPrime = true;
            for (long long i = 2; i <= primeNum / 2; ++i) {
                if (primeNum % i == 0) {
                    isPrime = false;
                    break;
                }
            }
        ++primeNum;
    }
    --primeNum;
//    std::cout << "Server has found a sufficient prime, " << primeNum << std::endl;

    return primeNum;
}

Reply Server::getEncryptedMessage(const int socketFD) {
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
        messageData decryptedMessage;
        messageReducedData encryptedMessage;
        n = read(socketFD, &encryptedMessage, sizeof(messageReducedData));
        if (n < 0) {
            perror("Error reading from socket");
        }
        userData user;
        strncpy(user.login, decryptedMessage.to, 24);
        bool isExisting;
        isExisting = this->checkRegisteredUser(user);
        if (isExisting) {
                messageData fullMessage;
                strncpy(fullMessage.from, currentLogin.c_str(), currentLogin.size());
                strncpy(fullMessage.to, decryptedMessage.to, 24);
                strncpy(fullMessage.text, decryptedMessage.text, 256);

                auto it = this->privateKeyMap.find(getLoginByAuthorization(socketFD));
                long long tempKey = it->second;
                decryptedMessage = fullMessage;

                std::string from = decryptedMessage.from;
                std::string to = decryptedMessage.to;
                std::string text = decryptedMessage.text;

                for (int i = 0; i < from.length(); ++i) {
                    decryptedMessage.from[i] = (fullMessage.from[i] - (tempKey% 74));
                }
                for (int i = 0; i < to.length(); ++i) {
                    decryptedMessage.to[i] = (fullMessage.to[i] - (tempKey% 74));
                }
                if (this->checkFriend(user.login, decryptedMessage.to)) {
                for (int i = 0; i < text.length(); ++i) {
                    decryptedMessage.text[i] = (fullMessage.text[i] - (tempKey% 74));
                }

                this->addNewEncryptedMessage(decryptedMessage);
                reply = Reply::Success;
            } else {
                reply = Reply::Failure;
            }
        } else{
            reply = Reply::Disagree;
        }
    } else {
        reply = Reply::Denied;

    }

    return reply;
}

void Server::addNewEncryptedMessage(const messageData &message) {
    pthread_mutex_lock(&this->unreadMessagesListMutex);
    this->unreadEncryptedMessages.push_back(message);
    pthread_mutex_unlock(&this->unreadMessagesListMutex);
    std::cout<< "Uspesne pridana nova encrypted sprava na neskorsie zpracovanie." << std::endl;
}

    Reply Server::sendNewEncryptedMessages(const int socketFD){
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
            for (auto it = this->unreadEncryptedMessages.begin(); it != this->unreadEncryptedMessages.end(); ++it) {
                if (currentLogin == (*it).to) {
                    newMessagesNumber++;
                }
            }
            pthread_mutex_unlock(&this->unreadMessagesListMutex);

            std::cout << "You have received " << newMessagesNumber<< " new encrypted messages. " << std::endl;
            n = write(socketFD, &newMessagesNumber, sizeof(int));
            if (n < 0) {
                perror("Error writing to socket");
            }

            if (newMessagesNumber != 0) {
                pthread_mutex_lock(&this->unreadMessagesListMutex);
                messageData decryptedMessage;
                messageData encryptedMessage;

                auto it = this->privateKeyMap.find(currentLogin);
                long long tempKey = it->second;

                for (auto it = this->unreadEncryptedMessages.begin(); it != this->unreadEncryptedMessages.end();) {
                    if (currentLogin == (*it).to) {
                        decryptedMessage = (*it);
                        encryptedMessage = (*it);

                        std::string from = decryptedMessage.from;
                        std::string to = decryptedMessage.to;
                        std::string text = decryptedMessage.text;


                        std::cout << "Decrypted message: From: " << decryptedMessage.from << " to: " << decryptedMessage.to << " text: " << decryptedMessage.text << std::endl;
                        for (int i = 0; i < from.length(); ++i) {
                            encryptedMessage.from[i] = (from[i] + (tempKey% 74));
                        }
                        for (int i = 0; i < to.length(); ++i) {
                            encryptedMessage.to[i] = (to[i] + (tempKey% 74));
                        }
                        for (int i = 0; i < text.length(); ++i) {
                            encryptedMessage.text[i] = (text[i] + (tempKey% 74));
                        }
                        std::cout << "Encrypted message: From: " << encryptedMessage.from << " to: " << encryptedMessage.to << " text: " << encryptedMessage.text << std::endl;
                        n = write(socketFD, &(*it), sizeof(messageData));
                        if (n < 0) {
                            perror("Error writing to socket");
                        }
                        it = this->unreadEncryptedMessages.erase(it);
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