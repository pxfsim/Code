#ifndef __CALLBACK_H__
#define __CALLBACK_H__

#include "dpi.h"

void my_callback(u_char *user,const struct pcap_pkthdr *pkr,const u_char *data);

#endif  //__CALLBACK_H__
