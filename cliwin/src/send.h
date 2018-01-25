

#include "dev.h"

#include <winsock2.h>
#include <iphlpapi.h>

#define HAVE_REMOTE
#include <pcap.h>
#include <pthread.h>

using namespace std;

int fnGetCPUNum(){
	SYSTEM_INFO si;  
    GetSystemInfo(&si);  
    return si.dwNumberOfProcessors;
}


unsigned short fnCheckSum(unsigned short packet[], int size )
{
	unsigned long lCksum = 0;
    while (size > 1) 
    {
        lCksum += *packet++;
        size -= sizeof(USHORT);
    }
    if (size) 
    {
        lCksum += *(UCHAR*)packet;
    }
    lCksum = (lCksum >> 16) + (lCksum & 0xFFFF);
    lCksum += (lCksum >>16);
    return (USHORT)(~lCksum);
}



int fnEncodePacket( byte packet[], const char *lpszSrcIpAddr,int nSrcPort, const char *lpszDstIpAddr,int nDstPort,byte tempSMac[], byte tempDMac[])
{
	TCP_HEADER tcpHeader;
	memset(&tcpHeader, 0, sizeof tcpHeader );
	*(unsigned short *)tcpHeader.srcPort = htons(nSrcPort);
	*(unsigned short *)tcpHeader.dstPort = htons(nDstPort);
	*(unsigned int *)tcpHeader.seqNumber = htonl(0xFFFF);
	*(unsigned int *)tcpHeader.ackNumber = htonl(0x00);
	tcpHeader.headLen = 5 << 4; 
	tcpHeader.contrl = 1 << 1;
	*(unsigned short *)tcpHeader.wndSize = htons(0xFFFF);
	
	IP_HEADER ipHeader;
	memset( &ipHeader, 0, sizeof ipHeader );
	unsigned char versionAndLen = 0x04;
	versionAndLen <<= 4;
	versionAndLen |= sizeof ipHeader / 4; //版本 + 头长度
	ipHeader.versionAndHeader = versionAndLen;
	*(unsigned short *)ipHeader.totalLen = htons( sizeof(IP_HEADER) + sizeof(TCP_HEADER) ); 
	ipHeader.ttl = 0xFF;
	ipHeader.hiProtovolType = PROTOCOL_TCP;
	*(unsigned int *)(ipHeader.srcIpAddr) = inet_addr(lpszSrcIpAddr);
	*(unsigned int *)(ipHeader.dstIpAddr) = inet_addr(lpszDstIpAddr);

	
	//BYTE tempSMac[6]={0x1C,0x1B,0x0D,0xBD,0xA6,0xD5};
	//BYTE tempDMac[6]={0xa4,0x56,0x02,0xf7,0x05,0xe7};

	ETHERNET_HEADER ethHeader;
	memset(&ethHeader, 0, sizeof ethHeader);
	if(tempSMac!=NULL)
		memcpy(ethHeader.srcMacAddr, tempSMac, 6);
	memcpy(ethHeader.dstMacAddr, tempDMac, 6);
	*(unsigned short *)ethHeader.ethernetType = htons(ETH_IP_V4);
	

	
	memcpy(packet, &ethHeader, sizeof ethHeader);
	memcpy(packet + sizeof ethHeader, &ipHeader, sizeof ipHeader);
	memcpy(packet + sizeof ethHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader);
	//printf("\nEncode Syn Packet Succeed\n");
	return (sizeof ethHeader + sizeof ipHeader + sizeof tcpHeader);
}