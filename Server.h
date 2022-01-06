#ifndef SERVER_SERVER_H
#define SERVER_SERVER_H

#include "data.h"

#include <pthread.h>
#include <list>
#include <string>

class Server {
public:
    static Server &getInstance() {
        static Server instance;
        return instance;
    }

    Reply registerNewUser(const int socketFD);

    Reply unregisterUser(const int socketFD);

    Reply authorizeUser(const int socketFD);

    Reply deauthorizeUser(const int socketFD); // logout

    Reply getMessage(const int socketFD);

    Reply sendNewMessages(const int socketFD);

    Reply addFriend(const int socketFD);

    Reply removeFriend(const int socketFD);

    Reply getFriendRequests(const int socketFD);

    Reply getHistory(const int socketFD);

private:
    pthread_mutex_t usersFileMutex;

    pthread_mutex_t authorizedUsersFileMutex;

    pthread_mutex_t unreadMessagesListMutex;

    pthread_mutex_t friendListFileMutex;

    pthread_mutex_t historyMutex;

    std::list<messageData> unreadMessages;

    Server();

    ~Server();
    bool checkRegisteredUser(const userData &user, const bool comparePassword = false);

    bool checkAuthorization(const int socketFD);

    void addNewUser(const userData &newUser);

    void addNewIP(const std::string newIP, const std::string registeredLogin);

    void deleteRegisteredUser(const std::string registeredLogin);

    void deleteAuthorizedIP(const std::string authorizedIP);

    std::string getIP(const int socketFD);

    std::string getLoginByAuthorization(const int socketFD);

    void addNewMessage(const messageData &message);

    bool checkFriend(const std::string currentLogin, const std::string friendLogin, const bool bilateralCheck = false, const bool checkConfirmation = false);

    void addToFriendList(const std::string currentLogin, const std::string friendLogin);

    void deleteFromFriendList(const std::string currentLogin, const std::string friendLogin);

    int getFriendRequestsNumber(const std::string login);

    int* getHistoryIndexes(const std::string login);

    std::string encryptPassword(std::string password);


public:
    Server(Server const &) = delete;

    void operator=(Server const &) = delete;
};

#endif //SERVER_SERVER_H
