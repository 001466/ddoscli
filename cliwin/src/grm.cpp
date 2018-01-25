/*

g++ -ogrm.exe grm.cpp -Wl,-Bstatic -lwsock32  -liphlpapi -lpthreadgc2 -Wl,-Bdynamic -lwpcap

*/

#include "dev.h"

bool getRemoteMac(char *remoteIP,char *remoteMac)            //获取远程主机MAC地址
{

 WSADATA wsaData;
 ULONG remoteAddr=0,macAddrLen=6;
 char remoteMacTemp[6]={0}; 

 if(WSAStartup(MAKEWORD(2,1), &wsaData)!=0)
 {
  printf("WSAStartup error!\n");
  return FALSE;
 }

 remoteAddr=inet_addr(remoteIP);
 if(SendARP(remoteAddr, (unsigned long)NULL,(PULONG)&remoteMacTemp, &macAddrLen)!=NO_ERROR)
 {
  printf("Get remote MAC failed!\n");
  return FALSE;
 }
 memcpy(remoteMac,remoteMacTemp,6);
/*
 for(int i=0; i<6; i++ )
 {
  printf( "%.2x", remoteMac[i] );
 }
 printf("\n");
*/
 return TRUE;
}

int main(int argc, char* argv[]){
	char lpszDstIp[32];
	fnHostToIP(argv[1],lpszDstIp);

	unsigned char lpszRemoteMac[32];
	//getRemoteMac(lpszDstIp,lpszRemoteMac);

	int nDevsNum=fnGetAllDevs(DEV_LIST);
	DEV_INFO dev=DEV_LIST[0];
	char szError[PCAP_ERRBUF_SIZE];
	pcap_t *pHandle = pcap_open_live(dev.szDevName, 65536, 0, 1000, szError );
	
	fnGetGateway(dev.szDevIP,dev.szDevGatewayIP);
	
	memset(dev.szDevGatewayMac, 0, sizeof dev.szDevGatewayMac);
	fnGetGatewayMacAddr(pHandle,dev.szDevIP,dev.szDevGatewayIP,dev.szDevGatewayMac);
	
	memset(dev.szDevMac, 0, sizeof dev.szDevMac);
    fnGetSelfMacAddr(dev.szDevMac); 

    dev.handle=pHandle; 

	fnGetGatewayMacAddr(pHandle,dev.szDevIP,lpszDstIp,lpszRemoteMac);


    printf("Mac:%02x.%02x.%02x.%02x.%02x.%02x\n", 	lpszRemoteMac[0],lpszRemoteMac[1],lpszRemoteMac[2],lpszRemoteMac[3],lpszRemoteMac[4],lpszRemoteMac[5]);

	printf("%s\n", lpszRemoteMac);
}