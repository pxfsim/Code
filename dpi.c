#include "dpi.h"


int main(int argc,char *argv[])
{

    int ret=0;
    if (argc!=2)
    {
        log_info("Error for file path\n");
        ret=1;
        goto err;
    }


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *fp=pcap_open_offline(argv[1],errbuf);
    if (fp==NULL)
    {
        log_info("Error for pcap_open_offline %s:%s\n",argv[1],errbuf);
        ret=2;
        goto err;
    }
    
    protocol_info_t *pi=protocol_info_init();

    pcap_loop(fp,-1,my_callback,(u_char *)pi);

    protocol_info_out(pi);
    protocol_info_free(pi);
    pcap_close(fp);
err:
    return ret;
}

