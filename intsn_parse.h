/* GNU LICENSE etc. etc.
 *
 * intsn_C
 *
 * -- adarqui (adarq.org / github.com/adarqui)
 */

#ifndef INTSN_PARSE_H
#define INTSN_PARSE_H

#include "intsn.h"

#define P_DATALINKS_MAX 110
#define P_NULLTYPES_MAX 11
#define P_ETHERTYPES_MAX 10
#define P_LAYERS3_4_MAX	60

typedef struct plink {
	void (*fn)(void *);
} plink_t;

plink_t p_datalinks[P_DATALINKS_MAX];
plink_t p_nulltypes[P_NULLTYPES_MAX];
plink_t p_layers3_4[P_LAYERS3_4_MAX];

void p_init(void);
void p_fill_datalinks(void);
void p_fill_layers3_4(void);

/* special */
void p_nullfn(void *);

/* datalink */
void p_decode_null(void *);
void p_decode_ethernet(void *);
void p_decode_ethernet_8021q(void *);
void p_decode_raw(void *);
void p_decode_wireless(void *);

/* layer 3 */
void p_decode_ipv4(void *);
void p_decode_ipv6(void *);
void p_decode_arp(void *);
void p_decode_icmp(void *);
void p_decode_udp(void *);
void p_decode_tcp(void *);
void p_decode_igmp(void *);
void p_decode_ipip(void *);
void p_decode_egp(void *);
void p_decode_ipv6_in_ipv4(void *);
void p_decode_gre(void *);
void p_decode_esp(void *);
void p_decode_ah(void *);
    

/* headers */
typedef struct hdr_eth {
	u_int8_t  dst[6];
	u_int8_t  src[6];
	u_int16_t type;
} hdr_eth_t;

typedef struct hdr_eth_vlan {
	u_int8_t dst[6];
	u_int8_t src[6];
	u_int16_t type;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int16_t vlan;
	u_int16_t vlan_type;
#elif defined (__BIG_ENDIAN_BITFIELD)
	u_int16_t vlan_type;
	u_int16_t vlan;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} hdr_eth_vlan_t;


typedef struct hdr_arp {
	u_int16_t		htype; 
	u_int16_t		ptype;
	u_int8_t		hlen;
	u_int8_t		plen;
	u_int16_t		op;
	u_int8_t 		sha[6];
	u_int8_t		sip[4];
	u_int8_t		tha[6];
	u_int8_t		tip[4];
} hdr_arp_t;


typedef struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    u_int8_t		ihl:4,
					version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	u_int8_t		version:4,
					ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	u_int8_t		tos;
	u_int16_t		tot_len;
	u_int16_t		id;
	u_int16_t		frag_off;
	u_int8_t		ttl;
	u_int8_t		proto;
	u_int16_t		cksum;
	u_int32_t		saddr;
	u_int32_t		daddr;
	/* options that I don't care about */
} hdr_ip_t;


typedef struct hdr_ipv6 {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int8_t		priority:4;
	u_int8_t		version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u_int8_t		version:4;
	u_int8_t		priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	u_int8_t		flow_lbl[3];
	u_int16_t		payload_len;
	u_int8_t		nexthdr;
	u_int8_t		hop_limit;
    struct  in6_addr    saddr;
    struct  in6_addr    daddr;
} hdr_ipv6_t;



typedef struct hdr_icmp {
  __u8      type;
  __u8      code;
  __sum16   checksum;
  union {
    struct {
        __be16  id;
        __be16  sequence;
    } echo;
    __be32  gateway;
    struct {
        __be16  __unused;
        __be16  mtu;
    } frag;
  } un;
} hdr_icmp_t;


typedef struct hdr_udp {
    __be16  sport;
    __be16  dport;
    __be16  len;
    __sum16 cksum;
} hdr_udp_t;


typedef struct hdr_tcp {
    __be16  sport;
    __be16  dport;
    __be32  seq;
    __be32  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
    __be16  window;
    __sum16 cksum;
    __be16  urg_ptr;
} hdr_tcp_t;



#endif
