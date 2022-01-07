#ifndef SERVER_DATA_H
#define SERVER_DATA_H

enum class Reply {
    Allowed = 0x0200, Denied, Success, Failure, Agree, Disagree
};

enum class Action {
    RegisterAccount = 0x0400, DeleteAccount, Login, Logout, SendMessage, GetNewMessages, AddFriend, RemoveFriend, GetFriendRequests, GetHistory, SendFile, GetNewFiles
};

struct userData {
    char login[24] = {0};
    char password[72] = {0};
};

struct messageData {
    char from[24] = {0};
    char to[24] = {0};
    char text[256] = {0};
};

struct messageReducedData {
    char to[24] = {0};
    char text[256] = {0};
};

struct fileData
{
    char from[24] = {0};
    char to[24] = {0};
    char name[128] = {0}; // with suffix
    char data[2048] = {0};
};

struct fileReducedData
{
    char to[24] = {0};
    char name[128] = {0}; // with suffix
    char data[2048] = {0};
};

#endif
