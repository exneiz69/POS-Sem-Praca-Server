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

    Reply sendFile(const int socketFD);

    Reply getNewFiles(const int socketFD);

    Reply createGroup(const int socketFD);

    Reply addUserToGroup(const int socketFD);

private:
    pthread_mutex_t usersFileMutex;

    pthread_mutex_t authorizedUsersFileMutex;

    pthread_mutex_t unreadMessagesListMutex;

    pthread_mutex_t friendListFileMutex;

    pthread_mutex_t historyMutex;

    pthread_mutex_t unreadFilesListMutex;

    pthread_mutex_t groupDataMutex;

    std::list<messageData> unreadMessages;

    std::list<fileData> unreadFiles;

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

    void addNewFile(const fileData &file);

    bool checkFriend(const std::string currentLogin, const std::string friendLogin, const bool bilateralCheck = false, const bool checkConfirmation = false);

    void addToFriendList(const std::string currentLogin, const std::string friendLogin);

    void deleteFromFriendList(const std::string currentLogin, const std::string friendLogin);

    int getFriendRequestsNumber(const std::string login);

    int* getHistoryIndexes(const std::string login);

    std::string encryptPassword(std::string password);

    bool checkGroup(const std::string groupName);

    void addNewGroup(const std::string groupName);

    bool checkUserInGroup(const std::string group, const std::string login);

    void addNewMessageGroup(messageData fullMessage, const std::string group, std::string login);

    std::list<std::string> getGroupNames(const std::string group, std::string login);

    void addNewFileGroup(const fileData &file, std::string group, std::string login);
public:
    Server(Server const &) = delete;

    void operator=(Server const &) = delete;
};

#endif //SERVER_SERVER_H
