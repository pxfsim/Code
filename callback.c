#include "dpi.h"

//传输层段识别
static int tcp_udp_packet_process(protocol_info_t *pi);

//IP报文识别
static int ip_packet_process(protocol_info_t * pi);

//应用层识别
static int detection_protocol(protocol_info_t *pi);


//主回调功能函数
void my_callback(u_char *user,const struct pcap_pkthdr *pkr,const u_char * data)
{

    //获取传入的protocol_info_t
    protocol_info_t *info=(protocol_info_t *)user;

    //统计总PACKET数量
    info->ptk_count++;

    //获取以太网帧
    info->ethhdr=(struct ethhdr *)data;

    //只处理IP协议
    if ( ntohs(info->ethhdr->h_proto)!=0x800)
        return;

    //统计PACKET数量
    info->ip_count++;

    //获取IP报文数据
    info->iphdr=(struct iphdr *)(data+sizeof(struct ethhdr));

    //调处理IP报文函数
    ip_packet_process(info);

    return;
}

static int ip_packet_process(protocol_info_t * pi)
{

    //只处理IPV4
    if (pi->iphdr->version!=4)
    {
        return -1;
    }

    //统计IPV4 PACKET数量
    pi->ipv4_count++;

    //调处理TCP/UDP报文函数
    tcp_udp_packet_process(pi);

    return 0;
}


static int tcp_udp_packet_process(protocol_info_t *pi)
{
    int ret=0;

    if ((ntohs(pi->iphdr->frag_off)&0x1FFF)!=0)
    {
        return -1;
    }
    ret=detection_protocol(pi);
    pi->protocol_types[ret]++;
    return ret;

}


static int detection_protocol(protocol_info_t *pi)
{

    int types=0;
    int i=0;

    //获取TCP/UDP数据报
    switch (pi->iphdr->protocol)
    {
    case IPPROTO_TCP:

        //获取TCP的数据
        pi->tcphdr=(struct tcphdr *)((char *)pi->iphdr+pi->iphdr->ihl*4);

        //遍历识别
        for(i=1;i<PRO_TYPES_MAX;i++)
        {
            if (pi->detec_func[i].func==NULL  )
                continue;
            if (pi->detec_func[i].flag==0) 
            {
                types=pi->detec_func[i].func(pi);
                if (types>0)
                {
                    break;
                }
            }
        }
        break;
    case IPPROTO_UDP:

        //获取UDP数据
        pi->udphdr=(struct udphdr *)((char *)pi->iphdr+pi->iphdr->ihl*4);

        //遍历识别
        for(i=1;i<PRO_TYPES_MAX;i++)
        {
            if (pi->detec_func[i].func==NULL  )
                continue;
            if (pi->detec_func[i].flag==1) 
            {
                types=pi->detec_func[i].func(pi);
                if (types>0)
                {
                    break;
                }
            }
        }
        break;
    }

    if (i==PRO_TYPES_MAX)
    {
        return 0;
    }

    return i;
}







