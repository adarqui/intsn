/* GNU LICENSE etc. etc.
 *
 * intsn_C
 *
 * -- adarqui (adarq.org / github.com/adarqui)
 */

#include "intsn.h"

int strlcatfmt(char *buf, int len, char *fmt, ...)
{
    va_list ap;
    int n;
    char tmp_buf[MAX_BUF_SZ];

	if(!buf || !fmt) return 0;

    va_start(ap, fmt);
    n = vsnprintf(tmp_buf, len, fmt, ap);
    if (n > sizeof(buf) - 1)
        n = sizeof(buf) - 1;
    else
        n = n;
    va_end(ap);

    n = strlcat(buf, tmp_buf, len);
    return n;
}

int ctoi(int c) {
	char buf[2];
	buf[0]=c;
	buf[1]='\0';
	return atoi(buf);
}

char * itoa(int n) {
	static char buf[12];
	snprintf(buf, sizeof(buf)-1, "%i", n);
	return buf;
}
