#include "ruby.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>



static VALUE
t_init (VALUE self)
{
	return self;
}

static VALUE
t_ipv4 (VALUE self,VALUE ipaddress)
{
  rb_iv_set (self, "@valid", (inet_addr(STR2CSTR(ipaddress)) == INADDR_NONE) ? Qfalse : Qtrue);
	return self;
}

static VALUE t_valid(VALUE self, VALUE anObject){
	return  rb_iv_get(self, "@valid");
}



static VALUE t_asn(VALUE self, VALUE ipaddress){
	char rev[256];
	char b0[4], b1[4], b2[4], b3[4];
	char * ip = STR2CSTR(ipaddress);
	unsigned char answer[PACKETSZ], host[128], *pt, *txt;
	int len, exp, cttl, size, txtlen, type;

	if (inet_addr(ip) != INADDR_NONE) {
		bzero(b0, 4);
		bzero(b1, 4);
		bzero(b2, 4);
		bzero(b3, 4);

		sprintf(b0, "%s", strtok(ip, "."));
		sprintf(b1, "%s", strtok(NULL, "."));
		sprintf(b2, "%s", strtok(NULL, "."));
		sprintf(b3, "%s", strtok(NULL, "."));

		sprintf(rev, "%s.%s.%s.%s.asn.routeviews.org", b3, b2, b1, b0);	

    if(res_init() < 0) {
			return Qnil;
    }

    memset(answer, 0, PACKETSZ);
    if((len = res_query(rev, C_IN, T_TXT, answer, PACKETSZ)) < 0) {
			return Qnil;
		}
	
    pt = answer + sizeof(HEADER);
    if((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0) {
			return Qnil;
		}
		pt += exp;
		GETSHORT(type, pt);
		if(type != T_TXT) {
			return Qnil;
		}
		pt += INT16SZ; /* class */
		if((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0) {
			return Qnil;
		}
		pt += exp;
		GETSHORT(type, pt);
		if(type != T_TXT) {
			return Qnil;
		}
		pt += INT16SZ; /* class */
		GETLONG(cttl, pt);
		GETSHORT(size, pt);
		txtlen = *pt;
		if(txtlen >= size || !txtlen) {
			return Qnil;
		}
		if(!(txt = malloc(txtlen + 1)))
			return Qnil;
		pt++;
		strncpy(txt, pt, txtlen);

		txt[txtlen] = 0;
	}
	return rb_str_new2(txt);

}


VALUE cIPTools;  

void
Init_IPTools()
{
	cIPTools = rb_define_class("IPTools", rb_cHash);
	rb_define_method (cIPTools,"initialize", t_init, 0);
	rb_define_method (cIPTools,"getasn", t_asn, 1);
	rb_define_method (cIPTools,"IPv4", t_ipv4, 1);
	rb_define_method (cIPTools,"valid?", t_valid, 0);
}
