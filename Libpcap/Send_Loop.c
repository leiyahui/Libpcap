
#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<arpa/inet.h>
char a[175]={
0x1,0x0,0x5e,0x7f,0xff,0xfa,0xfc,0x4d,0xd4,0x4c,0xf3,0xec,0x8,0x0,0x45,0x0,0x0,0xa1,0x4b,0x30,0x0,0x0,0x1,0x11,0x74,0xb2,0xca,0xcc,0x3e,0xa3,0xef,0xff,0xff,0xfa,0xdc,0x7a,0x7,0x6c,0x0,0x8d,0x7b,0x99,0x4d,0x2d,0x53,0x45,0x41,0x52,0x43,0x48,0x20,0x2a,0x20,0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0xd,0xa,0x48,0x6f,0x73,0x74,0x3a,0x32,0x33,0x39,0x2e,0x32,0x35,0x35,0x2e,0x32,0x35,0x35,0x2e,0x32,0x35,0x30,0x3a,0x31,0x39,0x30,0x30,0xd,0xa,0x53,0x54,0x3a,0x75,0x72,0x6e,0x3a,0x73,0x63,0x68,0x65,0x6d,0x61,0x73,0x2d,0x75,0x70,0x6e,0x70,0x2d,0x6f,0x72,0x67,0x3a,0x64,0x65,0x76,0x69,0x63,0x65,0x3a,0x49,0x6e,0x74,0x65,0x72,0x6e,0x65,0x74,0x47,0x61,0x74,0x65,0x77,0x61,0x79,0x44,0x65,
0x76,0x69,0x63,0x65,0x3a,0x31,0xd,0xa,0x4d,0x61,0x6e,0x3a,0x22,0x73,0x73,0x64,0x70,0x3a,0x64,0x69,0x73,0x63,0x6f,0x76,0x65,0x72,0x22,0xd,0xa,0x4d,0x58,0x3a,0x33,0xd,0xa,0xd,0xa};

	
int main()
{
	char* dev_str;
	char err[PCAP_ERRBUF_SIZE];
	unsigned char* packet;
	struct pcap_pkthdr p_pk;
	struct bpf_program fp;
	pcap_t* descr;
	dev_str=pcap_lookupdev(err);		//get the device string.if fail return error message to array err[PCAP_ERRBUF_SIZE];
	if(dev_str==NULL)
	{
		printf("%s\n",err);		//print error message
		exit(1);
	}
	descr=pcap_open_live(dev_str,65535,1,0,err);
	if(descr==NULL)
	{
		printf("%s\n",err);
		exit(1);
	}
	//pcap_compile(descr,&fp,"ip",1,0);
	//pcap_setfilter(descr,&fp);
	pcap_sendpacket(descr,a,175);
	return 0;
}