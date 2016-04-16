#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<arpa/inet.h>
typedef struct ethernet_packet	//ethernet packet
{
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short type;
}sniff_ethernet;
typedef struct ip_packet		//ip packet
{
	unsigned char v_hl;	//version 4bits and head length 4bits
	unsigned char diff;	//difference service
	unsigned short tot;	//totle length;
	unsigned short iden;		//identify
	unsigned short f_off;		//flag 3 bits and offset 13 bits
	unsigned char ttl;		//time to live
	unsigned char protocol;		
	unsigned short chk_sum;		//check sum
	unsigned char	src_addr[4];	//source address
	unsigned char	dst_addr[4];	//destination	address
}sniff_ip;
typedef struct tcp_packet		//tcp packet
{
	unsigned short src_port;	//source port;
	unsigned short dst_port;	//destination	port;
	unsigned int	seq;		//sequence number
	unsigned int	ack;		//acknowedge number
	unsigned short  o_s_m;		//data offset 4 bits and save 6 bits and urg bit,ack bit,psh bit rst bit syn bit fin bit
	unsigned short win;		//window value
	unsigned short chk_sum;		//check sum
	unsigned short urg_pointer;	//urgent pointer
}sniff_tcp;

void get_message(unsigned char* usr,const struct pcap_pkthdr* p_pk,const unsigned char* packet)
{
	int i;
	unsigned short host_short;
	unsigned int host_int;
	FILE* fp;
	fp=fopen("/home/leiyahui/Code/Libpcap/packet_output","a+");
	fprintf(fp,"packet length is:%d\n",p_pk->len);
	sniff_ethernet* ethernet;
	sniff_ip* ip;
	sniff_tcp* tcp;
	ethernet=(sniff_ethernet*)packet;
	ip=(sniff_ip*)(packet+sizeof(sniff_ethernet));
	tcp=(sniff_tcp*)(packet+sizeof(sniff_ethernet)+sizeof(sniff_ip));
	//ethernet packet
	fprintf(fp,"dst_mac is:%x:%x:%x:%x:%x:%x\n",ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5]);
	fprintf(fp,"src_mac is:%x:%x:%x:%x:%x:%x\n",ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[4],ethernet->src_mac[4],ethernet->src_mac[5]);
	host_short=ntohs(ethernet->type);
	fprintf(fp,"type is 0x:%04x\n",host_short);
	//ip packet
	fprintf(fp,"version is:%u\n",ip->v_hl>>4);
	fprintf(fp,"head length is:%u\n",ip->v_hl&0x0F);
	host_short=ntohs(ip->tot);
	fprintf(fp,"totle length is:%u\n",host_short);
	host_short=ntohs(ip->iden);
	fprintf(fp,"identify is:%u\n",host_short);
	fprintf(fp,"flag is:%d\n",(unsigned char)(ip->f_off>>5));
	//	offset 
	fprintf(fp,"protocol is:%u\n",ip->protocol);
	host_short=ntohs(ip->chk_sum);
	fprintf(fp,"check sum is:%u\n",ip->chk_sum);
	fprintf(fp,"source address is:%d.%d.%d.%d\n",ip->src_addr[0],ip->src_addr[1],ip->src_addr[2],ip->src_addr[3]);
	fprintf(fp,"destination address is:%d.%d.%d.%d\n",ip->dst_addr[0],ip->dst_addr[1],ip->dst_addr[2],ip->dst_addr[3]);	
	//tcp packet
	host_short=ntohs(tcp->src_port);
	fprintf(fp,"source port is:%u\n",host_short);
	host_short=ntohs(tcp->dst_port);
	fprintf(fp,"destination port is:%u\n",host_short);
	host_int=ntohl(tcp->seq);
	fprintf(fp,"sequence unmber is:%u\n",host_int);
	host_int=ntohl(tcp->ack);
	fprintf(fp,"acknowledge number is:%u\n",host_int);
	for(i=0;i<p_pk->len;i++)
	{
		fprintf(fp,"0x%x,",packet[i]);
	}
	fprintf(fp,"\n");
	printf("get it\n");
}
	
	
void main()
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
	pcap_compile(descr,&fp,"tcp",1,0);
	pcap_setfilter(descr,&fp);
	pcap_loop(descr,10,get_message,NULL);
}
	
