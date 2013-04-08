#include "intsn.h"


in_addr_t net_netmask(int prefix) {
	if(prefix==0) {
		return (~((in_addr_t) -1));
	}
	else {
		return (~((1<<(32-prefix))-1));
	}
}

in_addr_t net_network(in_addr_t addr, int prefix) {
	return (addr & net_netmask(prefix));
}

char * inet6_ntoa ( struct in6_addr in6 ) {
// rip
	static char buf[40];
	return inet6_ntoa_buf(buf, sizeof(buf)-1, in6);
}

char * inet6_ntoa_buf( char * buf, int len, struct in6_addr in6) {
	uint16_t *bytes = ( uint16_t* ) &in6;
	size_t n;
	n = snprintf ( buf, len, "%x:%x:%x:%x:%x:%x:%x:%x", ntohs(bytes[0]), ntohs(bytes[1]), ntohs(bytes[2]),
		ntohs(bytes[3]), ntohs(bytes[4]), ntohs(bytes[5]), ntohs(bytes[6]), ntohs(bytes[7]) );
	buf[n] = '\0';
	return buf;
}

/*
static const char * ipv6_ntoa ( const void *net_addr ) {
	return inet6_ntoa ( * ( ( struct in6_addr * ) net_addr ) );
}
*/
