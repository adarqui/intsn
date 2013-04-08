/* GNU LICENSE etc. etc.
 *
 * intsn_C
 *
 * -- adarqui (adarq.org / github.com/adarqui)
 */

#include "intsn.h"

void svcs_init(void) {

	svcs_parse();
	return;
}

void svcs_parse(void) {
	FILE * fp;
	char buf[132];
	int i, port;

	char * str, * str_service, *str_port;

	fp = fopen("/etc/services", "r");
	if(!fp) {
		noncrit("Unable to load /etc/services");
		return;
	}

	memset(buf,0,sizeof(buf));

	/* OMG this is dirty but I want more speed... , perfect "hash" of the ports.. 8| */
	base.services = (service_t *) calloc(65535+1,sizeof(service_t));
	if(!base.services) {
		error("svcs_parse");
	}
	base.services_cnt = 65535;

	i=0;
	while(1) {
		if(fgets(buf,sizeof(buf)-1,fp)==NULL)
			break;

		str = buf;
		str_service = strtok(str, "\t");
		if(!str_service) continue;
		str_port = strtok(NULL, "/");
		if(!str_port) continue;

		port = atoi(str_port);
		if(base.services[port].name != NULL) continue;

		base.services[port].name = strdup(str_service);

		i++;
	}

	return;
}
