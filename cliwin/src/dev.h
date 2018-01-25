
#include "adr.h"

#include <winsock2.h>
#include <iphlpapi.h>

#define HAVE_REMOTE
#include <pcap.h>


static struct DEV_INFO  DEV_LIST[16]; 

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



int fnCloseDevList(){

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

}
