/* GNU LICENSE etc. etc.
 *
 * intsn_C
 *
 * -- adarqui (adarq.org / github.com/adarqui)
 */

#include "intsn.h"

void p_init(void) {
	p_fill_datalinks();
	p_fill_layers3_4();
	return;
}

void p_nullfn(void *pobj) { 
	return;
}

void p_fill_layers3_4(void) {
	int i=0;
	p_layers3_4[0].fn = p_decode_ipv4;
	p_layers3_4[1].fn = p_decode_icmp;
	p_layers3_4[2].fn = p_decode_igmp;
	p_layers3_4[4].fn = p_decode_ipip;
	p_layers3_4[6].fn = p_decode_tcp;
	p_layers3_4[8].fn = p_decode_egp;
	p_layers3_4[17].fn = p_decode_udp;
	p_layers3_4[41].fn = p_decode_ipv6_in_ipv4;
	p_layers3_4[47].fn = p_decode_gre;
	p_layers3_4[50].fn = p_decode_esp;
	p_layers3_4[51].fn = p_decode_ah;

	for(i=0;i<(sizeof(p_layers3_4)/sizeof(plink_t));i++) {
        if(!p_layers3_4[i].fn) {
            p_layers3_4[i].fn = p_nullfn;
        }
    }

	return;
}

void p_fill_datalinks(void) {
	int i;
	p_datalinks[0].fn = p_decode_null;
	p_datalinks[1].fn = p_decode_ethernet;
	p_datalinks[12].fn = p_decode_raw;
	p_datalinks[14].fn = p_decode_raw;
	p_datalinks[105].fn = p_decode_wireless;

	for(i=0;i<(sizeof(p_datalinks)/sizeof(plink_t));i++) {
		if(!p_datalinks[i].fn) {
			p_datalinks[i].fn = p_nullfn;
		}
	}

	return;
}


/* datalink */
void p_decode_null(void *p) {
	pobj_t * pobj;
	int family;
 
	if(!p) return;
	pobj = (pobj_t *) p;

	family = *(u_int16_t *)pobj->pkt.raw;

	pobj->pkt.off+=4;
	switch(family) {
		case 2: {
			p_decode_ipv4(pobj);
			break;
		}
		case 10: {
			p_decode_ipv6(pobj);
			break;
		}
		default: {
		}
	}

	return;
}

void p_decode_ethernet(void *p) {
	pobj_t *pobj;
	hdr_eth_t * eth;

	unsigned short type;
	size_t sz;
	int vlan=-1;

	if(!p) return;
	pobj = (pobj_t *) p;

	eth = (hdr_eth_t *) pobj->pkt.raw + pobj->pkt.off;	

	sz = sizeof(hdr_eth_t);
	type = ntohs(eth->type);

	if(type == 0x8100) {
		hdr_eth_vlan_t * eth_vlan;
		eth_vlan = (hdr_eth_vlan_t *) (pobj->pkt.raw + pobj->pkt.off);
		vlan = ntohs(eth_vlan->vlan);
		type = ntohs(eth_vlan->vlan_type);
		pobj->intf.vlan = 1;
		sz += 4;

		pobj_layers_add(pobj, INFO_PATH, "(%i)", vlan);
	}

	pobj->pkt.off+=sz;

	if(base.opts.e > 0) {

		if(pobj->intf.vlan > 0) {
			pobj_layers_add(pobj, INFO_DESC, "VLAN %i", vlan);
		}
        
		pobj_layers_add(pobj, INFO_SRC, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", 
			eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);

		pobj_layers_add(pobj, INFO_DST, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
	}

	switch(type) {
		case 0x800: {
			p_decode_ipv4(pobj);	
			break;
		}
		case 0x806: {
			p_decode_arp(pobj);
			break;
		}
		case 0x86dd: {
			p_decode_ipv6(pobj);
			break;
		}
		case 0x8100: {
			/* 802.1q */
			p_decode_ethernet_8021q(pobj);
			break;
		}
		default: {
		}
	}

	return;
}



void p_decode_raw(void *p) {
	pobj_t * pobj;

	if(!p) return;
	pobj = (pobj_t *)p;

	p_decode_ipv4(pobj);
	return;
}

void p_decode_wireless(void *p) {
	pobj_t * pobj;

	if(!p) return;
	pobj = (pobj_t *) p;

	return;
}


void p_decode_arp(void *p) {
	pobj_t * pobj;
	hdr_arp_t * arp;

	struct in_addr src, dst;
	char * str_src, *str_dst;

	if(!p) return;
	pobj = (pobj_t *) p;
	pobj_layers_add(pobj, INFO_PATH, ":%s",  "arp");

	arp = (hdr_arp_t *)(pobj->pkt.raw + pobj->pkt.off);

	arp->htype	= ntohs(arp->htype);
	arp->ptype	= ntohs(arp->ptype);
	arp->op		= ntohs(arp->op);
	
	pobj_layers_add(pobj, INFO_DATA, "ARP");

	if(arp->hlen == 6 && arp->plen == 4) {
		src.s_addr = *(in_addr_t *)arp->sip;
		dst.s_addr = *(in_addr_t *)arp->tip;

		str_src = strdup(inet_ntoa(src));
		str_dst = strdup(inet_ntoa(dst));

		pobj_layers_add(pobj, INFO_DATA, "who-has %s tell %s", str_dst, str_src);
		free(str_src);
		free(str_dst);
	}


	return;
}


void p_decode_ipv4(void *p) {
	pobj_t * pobj;
	hdr_ip_t * ip;

	struct in_addr s;
	struct in_addr d;

	if(!p) return;
	pobj = (pobj_t *) p;

	ip = (hdr_ip_t *) (pobj->pkt.raw + pobj->pkt.off);	

	if(ip->version == 6) {
		p_decode_ipv6(p);
		return;
	}

	if(ip->proto >= P_LAYERS3_4_MAX) return;

	pobj_layers_add(pobj, INFO_PATH, ":%s", "ipv4");

	ip->tot_len = ntohs(ip->tot_len);

	s.s_addr = ip->saddr;
	d.s_addr = ip->daddr;

	pobj_layers_add(pobj, INFO_DESC, "IP");
	pobj_layers_add(pobj, INFO_SRC, "%s", inet_ntoa(s));
	pobj_layers_add(pobj, INFO_DST, "%s", inet_ntoa(d));


	pobj->pkt.off += (ip->ihl*4);
	p_layers3_4[ip->proto].fn((pobj_t *)pobj);	

	return;
}

void p_decode_ipv6(void *p) {
	pobj_t * pobj;
	hdr_ipv6_t * ipv6;

	char buf_src[41], buf_dst[41];


	if(!p) return;
	pobj = (pobj_t *) p;
	pobj_layers_add(pobj, INFO_PATH, ":%s", "ipv6");

	ipv6 = (hdr_ipv6_t *) (pobj->pkt.raw + (pobj->pkt.off));

	if(ipv6->nexthdr >= P_LAYERS3_4_MAX) return;

	inet6_ntoa_buf(buf_src, sizeof(buf_src)-1, ipv6->saddr);
	inet6_ntoa_buf(buf_dst, sizeof(buf_dst)-1, ipv6->daddr);

	pobj_layers_add(pobj, INFO_DESC, "IP6");
	pobj_layers_add(pobj, INFO_SRC, "%s", buf_src);
	pobj_layers_add(pobj, INFO_DST, "%s", buf_dst);

	pobj->pkt.off += sizeof(hdr_ipv6_t);
	p_layers3_4[ipv6->nexthdr].fn((pobj_t *)pobj);


	return;
}




void p_decode_icmp(void *p) {
	pobj_t * pobj;
	hdr_icmp_t * icmp;
	char buf[132];
	int len;

	if(!p) return;
	pobj = (pobj_t *) p;
	pobj_layers_add(pobj, INFO_PATH, ":%s", "icmp");

	icmp = (hdr_icmp_t *) (pobj->pkt.raw + pobj->pkt.off);
	
	buf[0] = '\0';
	if(icmp->type == 0 || icmp->type == 8) {
		snprintf(buf,sizeof(buf)-1," id %i seq %i", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
	}

	len = (pobj->pkt.phdr->caplen - pobj->pkt.off);
	if(icmp->type == 8 || icmp->type == 0) {
		pobj_layers_add(pobj, INFO_DATA, "ICMP type %s%s len %i", icmp->type == 8 ? "ping" : "pong", buf, len);
	}
	else {
		pobj_layers_add(pobj, INFO_DATA, "ICMP type %i code %i%s len %i", icmp->type, icmp->code, buf, len);
	}

	return;
}

void p_decode_udp(void *p) {
	pobj_t * pobj;
	hdr_udp_t *udp;

	if(!p) return;
	pobj = (pobj_t *) p;
	pobj_layers_add(pobj, INFO_PATH, ":%s", "udp");

	udp = (hdr_udp_t *) (pobj->pkt.raw + pobj->pkt.off);

	if(base.opts.s) {
		pobj_layers_add(pobj, INFO_SRC, "%s", base.services[udp->sport].name != NULL ? base.services[udp->sport].name : itoa(udp->sport));
		pobj_layers_add(pobj, INFO_DST, "%s", base.services[udp->dport].name != NULL ? base.services[udp->dport].name : itoa(udp->dport));
	}
	else {
		pobj_layers_add(pobj, INFO_SRC, "%i", udp->sport);
		pobj_layers_add(pobj, INFO_DST, "%i", udp->dport);
	}

	pobj_layers_add(pobj, INFO_DATA, "UDP len %i", ntohs(udp->len)-sizeof(hdr_udp_t));

	return;
}



void p_decode_tcp(void *p) {
	pobj_t * pobj;
	hdr_tcp_t *tcp;
	char buf[132];
	int len;

	if(!p) return;
	pobj = (pobj_t *) p;
	pobj_layers_add(pobj, INFO_PATH, ":%s", "tcp");

	tcp = (hdr_tcp_t *) (pobj->pkt.raw + pobj->pkt.off);
	tcp->sport = ntohs(tcp->sport);
	tcp->dport = ntohs(tcp->dport);

	if(base.opts.s) {
		pobj_layers_add(pobj, INFO_SRC, "%s", base.services[tcp->sport].name != NULL ? base.services[tcp->sport].name : itoa(tcp->sport));
		pobj_layers_add(pobj, INFO_DST, "%s", base.services[tcp->dport].name != NULL ? base.services[tcp->dport].name : itoa(tcp->dport));
	}
	else {
		pobj_layers_add(pobj, INFO_SRC, "%i", tcp->sport);
		pobj_layers_add(pobj, INFO_DST, "%i", tcp->dport);
	}

	buf[0]='\0';
	if(tcp->ack) {
		strncat(buf," ACK",sizeof(buf)-1);
	}
	if(tcp->psh) {
		strncat(buf," PSH",sizeof(buf)-1);
	}
	if(tcp->rst) {
		strncat(buf," RST",sizeof(buf)-1);
	}
	if(tcp->syn) {
		strncat(buf," SYN",sizeof(buf)-1);
	}
	if(tcp->fin) {
		strncat(buf," FIN",sizeof(buf)-1);
	}

	len = (pobj->pkt.phdr->caplen - pobj->pkt.off) - (tcp->doff*4);
	pobj_layers_add(pobj, INFO_DATA, "TCP seq %li ack %li%s len %i", ntohl(tcp->seq), ntohl(tcp->ack_seq), buf, len);

	return;
}


void p_decode_igmp(void *p) { pobj_t * pobj; if(!p) return; pobj = (pobj_t *) p; pobj_layers_add(pobj, INFO_PATH, ":%s", "igmp"); pobj_layers_add(pobj, INFO_DATA, "IGMP"); return; }
void p_decode_ipip(void *p) { pobj_t * pobj; if(!p) return; pobj = (pobj_t *) p; pobj_layers_add(pobj, INFO_PATH, ":%s", "ipip"); pobj_layers_add(pobj, INFO_DATA, "IPIP"); return; }
void p_decode_egp(void *p) { pobj_t * pobj; if(!p) return; pobj = (pobj_t *) p; pobj_layers_add(pobj, INFO_PATH, ":%s", "egp"); pobj_layers_add(pobj, INFO_DATA, "EGP"); return; } 
void p_decode_ipv6_in_ipv4(void *p) { pobj_t * pobj; if(!p) return; pobj = (pobj_t *) p; pobj_layers_add(pobj, INFO_PATH, ":%s", "ipv6_in_ipv4"); return; }
void p_decode_gre(void *p) { pobj_t * pobj; if(!p) return; pobj = (pobj_t *) p; pobj_layers_add(pobj, INFO_PATH, ":%s", "gre"); pobj_layers_add(pobj, INFO_DATA, "GRE"); return; }
void p_decode_esp(void *p) { pobj_t * pobj; if(!p) return; pobj = (pobj_t *) p; pobj_layers_add(pobj, INFO_PATH, ":%s", "esp"); pobj_layers_add(pobj, INFO_DATA, "IPSEC ESP"); return; }
void p_decode_ah(void *p) { pobj_t * pobj; if(!p) return; pobj = (pobj_t *) p; pobj_layers_add(pobj, INFO_PATH, ":%s", "ah"); pobj_layers_add(pobj, INFO_DATA, "IPSEC AH"); return; }
void p_decode_ethernet_8021q(void *p) { pobj_t * pobj; if(!p) return; pobj = (pobj_t *) p; pobj_layers_add(pobj, INFO_PATH, ":%s", "802.1q"); pobj_layers_add(pobj, INFO_DATA, "EN 802.1q"); return; }
