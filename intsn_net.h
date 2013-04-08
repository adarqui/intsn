#ifndef INTSN_NET_H
#define INTSN_NET_H

#include "intsn.h"

in_addr_t net_netmask(int prefix);
char * inet6_ntoa ( struct in6_addr in6 );
char * inet6_ntoa_buf ( char *, int, struct in6_addr);
/*static const char * ipv6_ntoa ( const void *net_addr ); */

#endif
