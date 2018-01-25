
/*

g++ -ohtn.exe htn.cpp -Wl,-Bstatic -lwsock32  -liphlpapi 

*/

#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
int main(int argc, char* argv[]){


    WSADATA wsaData;
    WSAStartup( MAKEWORD(2, 2), &wsaData);

    struct hostent *host = gethostbyname(argv[1]);
    printf("Address type: %s\n", (host->h_addrtype==AF_INET) ? "AF_INET": "AF_INET6");
    //IP地址
    for(int i=0; host->h_addr_list[i]; i++){
        printf("IP addr %d: %s\n", i+1, inet_ntoa( *(struct in_addr*)host->h_addr_list[i] ) );
    }
    
    return 0;
}