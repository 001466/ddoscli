
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string>
#include <iphlpapi.h>

#define HAVE_REMOTE
#include <pcap.h>


#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ETH_IP_V4       0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址

#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ARP_REQUEST     1  //ARP请求
#define ARP_REPLY       2  //ARP应答

#define PROTOCOL_TCP    0x06
#define PROTOCOL_UDP    0x11
#define PROTOCOL_ICMP   0x06
#define PROTOCOL_IGMP   0x06

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
    pcap_t*             handle;
    char                szDevName[512];
    char                szDevDescription[512];
    char                szDevIP[64];
    unsigned char       szDevMac[64];
    char                szDevNetmask[64]; 
    char                szDevGatewayIP[64];
    unsigned char       szDevGatewayMac[64];

};

 
 //28字节ARP帧结构
struct ARP_HEADER {
    unsigned short  snHardwareType; //硬件类型
    unsigned short  snProtocolType; //协议类型
    unsigned char   cHardwareAddLen; //硬件地址长度
    unsigned char   cProtocolAddLen; //协议地址长度
    unsigned short  snOperationField; //操作字段
    unsigned char   szSourceMacAdd[6]; //源mac地址
    unsigned char   szSourceIpAdd[4]; //源ip地址
    unsigned char   szDestMacAdd[6]; //目的mac地址
    unsigned char   szDestIpAdd[4]; //目的ip地址
};






int fnGetSelfMacAddr(unsigned char *pMac)
{

    IP_ADAPTER_INFO adapter[5];  //Maximum 5 adapters
    DWORD buflen=sizeof(adapter);
    DWORD status=GetAdaptersInfo(adapter,&buflen);
    if(status==ERROR_SUCCESS)
    {
        PIP_ADAPTER_INFO painfo=adapter;
        memcpy(pMac,painfo->Address,6);
        return true;
    }else{
        return false;
    }
}



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
       //printf("Send ARP Packet Succeed ... \n");
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


int fnHostToIP(char* pcHost, char *pcIP){

    WSADATA wsaData;
    
    WSAStartup( MAKEWORD(2, 2), &wsaData);

    struct hostent *host = gethostbyname(pcHost);
     
    sprintf(pcIP,"%s", inet_ntoa( *(struct in_addr*)host->h_addr_list[0] ) );

    return 0;
}