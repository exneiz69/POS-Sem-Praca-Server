#ifndef SERVER_SERVER_H
#define SERVER_SERVER_H

#include "data.h"

#include <pthread.h>
#include <list>
#include <string>
#include <map>

class Server {
public:
    static Server &getInstance() {
        static Server instance;
        return instance;
    }

    Reply registerNewUser(int socketFD);

    Reply unregisterUser(int socketFD);

    Reply authorizeUser(int socketFD);

    Reply deauthorizeUser(int socketFD); // logout

    Reply getMessage(int socketFD);

    Reply sendNewMessages(int socketFD);

    Reply getEncryptedMessage(int socketFD);

    Reply sendNewEncryptedMessages(int socketFD);

    Reply sendPublicKey(int socketFD);

    Reply buildSymmetricConnection(int socketFD);

    Reply addFriend(int socketFD);

    Reply removeFriend(int socketFD);

    Reply getFriendRequests(int socketFD);

    Reply getHistory(int socketFD);

    Reply sendFile(int socketFD);

    Reply getNewFiles(int socketFD);

    Reply createGroup(int socketFD);

    Reply addUserToGroup(int socketFD);

    long long getG();

    long long getP();

private:
    pthread_mutex_t usersFileMutex{};

    pthread_mutex_t authorizedUsersFileMutex{};

    pthread_mutex_t unreadMessagesListMutex{};

    pthread_mutex_t unreadEncryptedMessagesListMutex{};

    pthread_mutex_t friendListFileMutex{};

    pthread_mutex_t historyFileMutex{};

    pthread_mutex_t unreadFilesListMutex{};

    pthread_mutex_t groupsFileMutex{};

    std::list<messageData> unreadMessages;

    std::list<messageData> unreadEncryptedMessages;

    std::list<fileData> unreadFiles;

    std::map<std::string,long long> privateKeyMap;

    long long P = 4745186671;

    long long G = 0;

    Server();

    ~Server();

    bool checkRegisteredUser(const userData &user, bool comparePassword = false);

    bool checkAuthorization(int socketFD);

    void addNewUser(const userData &newUser);

    void addNewIP(const std::string& newIP, const std::string& registeredLogin);

    void deleteRegisteredUser(const std::string& registeredLogin);

    void deleteAuthorizedIP(const std::string& authorizedIP);

    std::string getIP(int socketFD);

    std::string getLoginByAuthorization(int socketFD);

    void addNewMessage(const messageData &message);

    void addNewEncryptedMessage(const messageData &message);

    void addNewFile(const fileData &file);

    bool checkFriend(const std::string& currentLogin, const std::string& friendLogin, bool bilateralCheck = false, bool checkConfirmation = false);

    void addToFriendList(const std::string& currentLogin, const std::string& friendLogin);

    void deleteFromFriendList(const std::string& currentLogin, const std::string& friendLogin);

    int getFriendRequestsNumber(const std::string& login);

    int* getHistoryIndexes(const std::string& login);

    std::string encryptPassword(const std::string& password);

    long long diffieHelmanStepOne(long long prime);

    long long diffieHelmanStepTwo(long long privateKeyComponentClient, long long privateKeyBase);

    long long primeNumberGenerator();

    bool checkGroup(const std::string& groupName);

    void addNewGroup(const std::string& groupName);

    bool checkUserInGroup(const std::string& group, const std::string& login);

    void addNewMessageGroup(messageData fullMessage, const std::string& group, const std::string& login);

    std::list<std::string> getGroupNames(const std::string& group, const std::string& login);

    void addNewFileGroup(const fileData &file, const std::string& group, const std::string& login);

public:
    Server(Server const &) = delete;

    void operator=(Server const &) = delete;
};

#endif //SERVER_SERVER_H
