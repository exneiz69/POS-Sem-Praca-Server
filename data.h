#ifndef SERVER_DATA_H
#define SERVER_DATA_H

enum class Reply {
    Allowed = 0x0200, Denied, Success, Failure, Agree, Disagree
};

enum class Action {
    RegisterAccount = 0x0400, // 1024
    DeleteAccount,          // 1025
    Login,                  // 1026
    Logout,                 // 1027
    SendMessage,            // 1028
    GetNewMessages,         // 1029
    SendEncryptedMessage,   // 1030
    GetNewEncryptedMessages,// 1031
    GetPublicKey,           // 1032
    BuildSymmetricConnection,// 1033
    AddFriend,              // 1034
    RemoveFriend,           // 1035
    GetFriendRequests,      // 1036
    GetHistory,             // 1037
    SendFile,               // 1038
    GetNewFiles,            // 1039
    CreateGroup,            // 1040
    AddUserToGroup          // 1041
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

struct fileData {
    char from[24] = {0};
    char to[24] = {0};
    char name[128] = {0}; // with suffix
    char data[2048] = {0};
};

struct fileReducedData {
    char to[24] = {0};
    char name[128] = {0}; // with suffix
    char data[2048] = {0};
};

struct groupData {
    char name[24] = {0};
};

#endif
