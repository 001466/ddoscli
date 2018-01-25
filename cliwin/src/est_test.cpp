
/*
g++ -oest_test.exe est_test.cpp -Wl,-Bstatic -lwsock32  -liphlpapi -lpthreadgc2 -Wl,-Bdynamic -lwpcap
*/

#include <stdio.h>  
#include <stdlib.h>  
#include <pcap.h>  
#include <winsock2.h>  
#include <iostream>  
using namespace std;  
  
#pragma comment(lib, "../common/lib/Packet.lib")  
#pragma comment(lib, "../common/lib/wpcap.lib")  
#pragma comment(lib, "ws2_32.lib")  
  
  
/*                       IP报文格式 
0            8           16                        32 
+------------+------------+-------------------------+ 
| ver + hlen |  服务类型  |         总长度          | 
+------------+------------+----+--------------------+ 
|           标识位        |flag|   分片偏移(13位)   | 
+------------+------------+----+--------------------+ 
|  生存时间  | 高层协议号 |       首部校验和        | 
+------------+------------+-------------------------+ 
|                   源 IP 地址                      | 
+---------------------------------------------------+ 
|                  目的 IP 地址                     | 
+---------------------------------------------------+ 
*/  
  
struct IP_HEADER  
{  
    byte versionAndHeader;  
    byte serviceType;  
    byte totalLen[2];  
    byte seqNumber[2];  
    byte flagAndFragPart[2];  
    byte ttl;  
    byte hiProtovolType;  
    byte headerCheckSum[2];  
    byte srcIpAddr[4];  
    byte dstIpAddr[4];  
};  
  
/* 
                     TCP 报文 
0                       16                       32  
+------------------------+-------------------------+ 
|      源端口地址        |      目的端口地址       | 
+------------------------+-------------------------+ 
|                      序列号                      | 
+--------------------------------------------------+ 
|                      确认号                      | 
+------+--------+--------+-------------------------+ 
|HLEN/4| 保留位 |控制位/6|         窗口尺寸        | 
+------+--------+--------+-------------------------+ 
|         校验和         |         应急指针        | 
+------------------------+-------------------------+ 
*/  
  
struct TCP_HEADER  
{  
    byte srcPort[2];  
    byte dstPort[2];  
    byte seqNumber[4];  
    byte ackNumber[4];  
    byte headLen;  
    byte contrl;  
    byte wndSize[2];  
    byte checkSum[2];  
    byte uragentPtr[2];  
};  
  
struct PSDTCP_HEADER  
{   
    byte srcIpAddr[4];     //Source IP address; 32 bits  
    byte dstIpAddr[4];     //Destination IP address; 32 bits   
    byte padding;          //padding  
    byte protocol;         //Protocol; 8 bits  
    byte tcpLen[2];        //TCP length; 16 bits  
} ;  
  
struct ETHERNET_HEADER  
{    
    byte dstMacAddr[6];  
    byte srcMacAddr[6];  
    byte ethernetType[2];  
};  
  
  
char *FormatIpAddr( unsigned uIpAddr, char szIp[] )  
{  
    IN_ADDR addr;  
    addr.S_un.S_addr = uIpAddr;  
  
    strcpy( szIp, inet_ntoa( addr ) );  
    return szIp;  
}  
  
unsigned short CheckSum(unsigned short packet[], int size )  
{  
    unsigned long cksum = 0;  
    while (size > 1)   
    {  
        cksum += *packet++;  
        size -= sizeof(USHORT);  
    }  
    if (size)   
    {  
        cksum += *(UCHAR*)packet;  
    }  
    cksum = (cksum >> 16) + (cksum & 0xffff);  
    cksum += (cksum >>16);  
  
    return (USHORT)(~cksum);  
}  
  
void HandlePacketCallBack(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket)  
{  
    unsigned short localPort = *(unsigned short *)param;  
  
    ETHERNET_HEADER *pEthHeader = ( ETHERNET_HEADER *)recvPacket;  
    if ( *((unsigned short *)(pEthHeader->ethernetType)) != htons(0x0800) ) return;  
  
    IP_HEADER *pIpHeader = ( IP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER) );  
    if ( pIpHeader->hiProtovolType != 0x06 ) return;  
  
    TCP_HEADER *pTcpHeader = ( TCP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER) );  
    if ( *(unsigned short *)(pTcpHeader->dstPort) != htons(localPort) ) return ;  
  
    //////////////////////////////////////////////////////////////////////  
    IP_HEADER ipHeader;  
    memset( &ipHeader, 0, sizeof ipHeader );  
    unsigned char versionAndLen = 0x04;  
    versionAndLen <<= 4;  
    versionAndLen |= sizeof ipHeader / 4; //版本 + 头长度  
  
    ipHeader.versionAndHeader = versionAndLen;  
    *(unsigned short *)ipHeader.totalLen = htons( sizeof(IP_HEADER) + sizeof(TCP_HEADER) );   
  
    ipHeader.ttl = 0xFF;  
    ipHeader.hiProtovolType = 0x06;  
  
    memcpy(ipHeader.srcIpAddr, pIpHeader->dstIpAddr, sizeof(unsigned int) );  
    memcpy(ipHeader.dstIpAddr, pIpHeader->srcIpAddr, sizeof(unsigned int) );  
  
    *(unsigned short *)(ipHeader.headerCheckSum) = CheckSum( (unsigned short *)&ipHeader, sizeof ipHeader );  
  
    ////////////////////////////////////////////////////////////////////  
    unsigned int ack = ntohl(*(unsigned int *)(pTcpHeader->seqNumber));  
    unsigned int seq =  ntohl(*(unsigned int *)(pTcpHeader->ackNumber));  
  
    TCP_HEADER tcpHeader;  
    memset(&tcpHeader, 0, sizeof tcpHeader );  
    *(unsigned short *)tcpHeader.srcPort = htons(localPort);  
    *(unsigned short *)tcpHeader.dstPort = htons(80);  
    *(unsigned int *)tcpHeader.seqNumber = htonl(seq);  
    *(unsigned int *)tcpHeader.ackNumber = htonl(ack + 1);  
    tcpHeader.headLen = 5 << 4;   
    tcpHeader.contrl = 0x01 << 4; //  
    *(unsigned short *)tcpHeader.wndSize = htons(0xFFFF);  
  
    ///////////////////////////////////////////////////////////////////  
    PSDTCP_HEADER psdHeader;  
    memset(&psdHeader, 0x00, sizeof psdHeader);  
    psdHeader.protocol = 0x06;  
    *(unsigned short *)psdHeader.tcpLen = htons(sizeof(TCP_HEADER));  
    memcpy(psdHeader.dstIpAddr, ipHeader.dstIpAddr, sizeof(unsigned int) );  
    memcpy(psdHeader.srcIpAddr, ipHeader.srcIpAddr, sizeof(unsigned int) );  
  
    byte psdPacket[1024];  
    memcpy( psdPacket, &psdHeader, sizeof psdHeader );  
    memcpy( psdPacket + sizeof psdHeader, &tcpHeader, sizeof tcpHeader );  
  
    *(unsigned short *)tcpHeader.checkSum = CheckSum( (unsigned short*) psdPacket, sizeof psdHeader + sizeof tcpHeader );  
  
    ETHERNET_HEADER ethHeader;  
    memset(&ethHeader, 0, sizeof ethHeader);  
    memcpy(ethHeader.dstMacAddr, pEthHeader->srcMacAddr, 6);  
    memcpy(ethHeader.srcMacAddr, pEthHeader->dstMacAddr, 6);  
    *(unsigned short *)ethHeader.ethernetType = htons(0x0800);  
  
    byte packet[1024];  
    memset(packet, 0, sizeof packet);  
  
    memcpy(packet, &ethHeader, sizeof ethHeader);  
    memcpy(packet + sizeof ethHeader, &ipHeader, sizeof ipHeader);  
    memcpy(packet + sizeof ethHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader);  
  
    int size = sizeof ethHeader + sizeof ipHeader + sizeof tcpHeader;  
  
    pcap_t *handle = (pcap_t*)(param + sizeof(unsigned short));  
  
    byte data[] = "GET / HTTP/1.1\r\n\r\n";  
  
    char srcIp[32], dstIp[32];  
    byte ctrl = pTcpHeader->contrl & 0x3F;  
    switch ( ctrl )  
    {  
    case 0x01 << 1: //syn  
        break;  
    /*case 0x01 << 4: //ack 
        puts("收到ack"); 
        break;*/  
    case ((0x01 << 4) | (0x01 << 1)): //syn+ack  
  
        FormatIpAddr(*(unsigned int *)(pIpHeader->srcIpAddr), srcIp );  
        FormatIpAddr(*(unsigned int *)(pIpHeader->dstIpAddr), dstIp );  
        printf("%-16s ---SYN + ACK--> %-16s\n", srcIp, dstIp );  
  
        ///////////////////////////////////////////////////////////  
  
        pcap_sendpacket(handle, packet, size );  
        FormatIpAddr(*(unsigned int *)ipHeader.srcIpAddr, srcIp );  
        FormatIpAddr(*(unsigned int *)ipHeader.dstIpAddr, dstIp );  
        printf("%-16s ------ACK-----> %-16s\n", srcIp, dstIp );  
  
        Sleep(10);  
  
        pIpHeader = (IP_HEADER *)(packet + sizeof(ETHERNET_HEADER) );  
        *(unsigned short *)(pIpHeader->totalLen) = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER) + sizeof data );  
        memset(pIpHeader->headerCheckSum, 0x00, sizeof(unsigned short) );  
        *(unsigned short *)(pIpHeader->headerCheckSum) = CheckSum( (unsigned short *)pIpHeader, sizeof(IP_HEADER) );  
  
        pTcpHeader = (TCP_HEADER *)(packet + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER));  
        pTcpHeader->contrl = 0x01 << 4;  
        *(unsigned int *)(pTcpHeader->ackNumber) = htonl(ack+1);  
        *(unsigned int *)(pTcpHeader->seqNumber) = htonl(seq);  
        memset( pTcpHeader->checkSum, 0x00, sizeof(unsigned short) );  
  
        memset( psdPacket, 0x00, sizeof psdPacket );  
        *(unsigned short *)psdHeader.tcpLen = htons(sizeof(TCP_HEADER) + sizeof(data));  
  
        memcpy( psdPacket, &psdHeader, sizeof psdHeader );  
        memcpy( psdPacket + sizeof psdHeader, pTcpHeader, sizeof(TCP_HEADER) );  
        memcpy( psdPacket + sizeof psdHeader + sizeof(TCP_HEADER), data, sizeof data );  
  
        *(unsigned short *)(pTcpHeader->checkSum) = CheckSum( (unsigned short*) psdPacket, sizeof psdHeader + sizeof(TCP_HEADER) + sizeof data );  
  
        memcpy(packet, &ethHeader, sizeof ethHeader);  
        memcpy(packet + sizeof(ETHERNET_HEADER), pIpHeader, sizeof(IP_HEADER) );  
        memcpy(packet + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER), pTcpHeader, sizeof(TCP_HEADER) );  
        memcpy(packet + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER)+ sizeof(TCP_HEADER), data, sizeof data );  
          
        size += sizeof data;  
        pcap_sendpacket(handle, packet, size );  
          
        break;        
    default:  
        IP_HEADER *pIpHeader = (IP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER) );  
        unsigned short ipHeaderLen = pIpHeader->versionAndHeader & 0x0F;  
        ipHeaderLen *= 4;  
        TCP_HEADER *pTcpHeader = (TCP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER)  + ipHeaderLen );  
  
        int tcpHeaderLen = pTcpHeader->headLen >> 0x04;  
        tcpHeaderLen *= 4;  
        char *str = ( char *)(recvPacket + sizeof(ETHERNET_HEADER) + ipHeaderLen + tcpHeaderLen );  
        puts(str);  
    }  
    return;  
}  
  
int main()  
{  
    srand(time(0));  
    unsigned short srcPort = rand()%65535;//6382;  
    const char *lpszSrcIp = "192.168.0.63";  
    const char *lpszDstIp = "112.80.248.73";  
    const byte srcMac[] = {0x1c,0x1b,0x0d,0xbd,0xa6,0xd5};//主机mac  
    const byte dstMac[] = {0xa4,0x56,0x02,0xf7,0x05,0xe7}; //网关mac  
  
    char szError[1024];  
    //const char *lpszAdapterName = "\\Device\\NPF_{1DDB19E0-EC33-46E2-ACB5-085E87EF6489}";  
    const char *lpszAdapterName = "\\Device\\NPF_{D6C74E32-049D-456E-82A1-4D394A8F4679}";  

    pcap_t *handle = pcap_open_live(lpszAdapterName, 65536, 1, 1000, szError );  
    if ( NULL == handle ) return 0;  
  
    TCP_HEADER tcpHeader;  
    memset(&tcpHeader, 0, sizeof tcpHeader );  
    *(unsigned short *)tcpHeader.srcPort = htons(srcPort);  
    *(unsigned short *)tcpHeader.dstPort = htons(80);  
    *(unsigned int *)tcpHeader.seqNumber = htonl(0x00);  
    *(unsigned int *)tcpHeader.ackNumber = htonl(0x00);  
    tcpHeader.headLen = 5 << 4;   
    tcpHeader.contrl = 1 << 1;  
    *(unsigned short *)tcpHeader.wndSize = htons(0xFFFF);  
  
    PSDTCP_HEADER psdHeader;  
    memset(&psdHeader, 0, sizeof psdHeader);  
    *(unsigned int *)psdHeader.dstIpAddr = inet_addr(lpszSrcIp);  
    *(unsigned int *)psdHeader.srcIpAddr = inet_addr(lpszDstIp);  
    psdHeader.protocol = 0x06;  
    *(unsigned short *)psdHeader.tcpLen = htons(sizeof(TCP_HEADER));  
  
    byte psdPacket[1024];  
    memset(psdPacket, 0, sizeof psdPacket);  
    memcpy( psdPacket, &psdHeader, sizeof psdHeader );  
    memcpy( psdPacket + sizeof psdHeader, &tcpHeader, sizeof tcpHeader );  
  
    *(unsigned short *)tcpHeader.checkSum = CheckSum( (unsigned short*) psdPacket, sizeof psdHeader + sizeof tcpHeader );  
      
    IP_HEADER ipHeader;  
    memset( &ipHeader, 0, sizeof ipHeader );  
    unsigned char versionAndLen = 0x04;  
    versionAndLen <<= 4;  
    versionAndLen |= sizeof ipHeader / 4; //版本 + 头长度  
  
    ipHeader.versionAndHeader = versionAndLen;  
    *(unsigned short *)ipHeader.totalLen = htons( sizeof(IP_HEADER) + sizeof(TCP_HEADER) );   
  
    ipHeader.ttl = 0xFF;  
    ipHeader.hiProtovolType = 0x06;  
  
    *(unsigned int *)(ipHeader.srcIpAddr) = inet_addr(lpszSrcIp);  
    *(unsigned int *)(ipHeader.dstIpAddr) = inet_addr(lpszDstIp);  
    *(unsigned short *)(ipHeader.headerCheckSum) = CheckSum( (unsigned short *)&ipHeader, sizeof ipHeader );  
  
    ETHERNET_HEADER ethHeader;  
    memset(&ethHeader, 0, sizeof ethHeader);  
    memcpy(ethHeader.dstMacAddr, dstMac, 6);  
    memcpy(ethHeader.srcMacAddr, srcMac, 6);  
    *(unsigned short *)ethHeader.ethernetType = htons(0x0800);  
  
    byte packet[1024];  
    memset(packet, 0, sizeof packet);  
  
    memcpy(packet, &ethHeader, sizeof ethHeader);  
    memcpy(packet + sizeof ethHeader, &ipHeader, sizeof ipHeader);  
    memcpy(packet + sizeof ethHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader);  
      
    int size = sizeof ethHeader + sizeof ipHeader + sizeof tcpHeader;  
    pcap_sendpacket(handle, packet, size );  
    printf("%-16s ------SYN-----> %-16s\n", lpszSrcIp, lpszDstIp );  
  
    if ( NULL == handle )  
    {  
        printf("\nUnable to open the adapter. %s is not supported by WinPcap\n");  
        return 0;  
    }  
    byte param[1024];  
    memset(param, 0x00, sizeof param );  
    memcpy(param, &srcPort, sizeof srcPort );  
    memcpy(param + sizeof srcPort, handle, 512 );  
    pcap_loop( handle, -1, HandlePacketCallBack, param );  
    pcap_close(handle);   
    return 0;  
}  