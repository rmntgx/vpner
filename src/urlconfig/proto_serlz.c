#include <cjson/cJSON.h>
#include <utils.c>
#include <string.h>
#include "bean.c"

static cJSON* create_transport_object(const Bean* b) {
	if (!b || !b->type) return NULL;
	if (strcmp(b->type, "ws") == 0) {
		cJSON* trans = cJSON_CreateObject();
		cJSON_AddStringToObject(trans, "type", "ws");
		if (b->host && strlen(b->host)) {
			cJSON* headers = cJSON_CreateObject();
			cJSON_AddStringToObject(headers, "Host", b->host);
			cJSON_AddItemToObject(trans, "headers", headers);
		}
		cJSON_AddStringToObject(trans, "path",
								(b->path && strlen(b->path)) ? b->path : "/");
		return trans;
	} else if (strcmp(b->type, "grpc") == 0) {
		cJSON* trans = cJSON_CreateObject();
		cJSON_AddStringToObject(trans, "type", "grpc");
		cJSON_AddStringToObject(trans, "service_name",
								b->serviceName ? b->serviceName : "");
		return trans;
	} else if (strcmp(b->type, "http") == 0 || strcmp(b->type, "h2") == 0) {
		cJSON* trans = cJSON_CreateObject();
		cJSON_AddStringToObject(trans, "type", "http");
		cJSON_AddStringToObject(trans, "path",
								(b->path && strlen(b->path)) ? b->path : "/");
		if (b->host && strlen(b->host)) {
			cJSON* host_arr = cJSON_CreateArray();
			cJSON_AddItemToArray(host_arr, cJSON_CreateString(b->host));
			cJSON_AddItemToObject(trans, "host", host_arr);
		}
		return trans;
	} else if (strcmp(b->type, "httpupgrade") == 0) {
		cJSON* trans = cJSON_CreateObject();
		cJSON_AddStringToObject(trans, "type", "httpupgrade");
		cJSON_AddStringToObject(trans, "path", b->path ? b->path : "");
		if (b->host && strlen(b->host))
			cJSON_AddStringToObject(trans, "host", b->host);
		return trans;
	}
	return NULL;
}

static cJSON* generate_vless_obj(const Bean* b) {
	cJSON* o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "domain_strategy", "");
	if (b->packetEncoding == 1)
		cJSON_AddStringToObject(o, "packet_encoding", "packetaddr");
	else if (b->packetEncoding == 2)
		cJSON_AddStringToObject(o, "packet_encoding", "xudp");
	cJSON_AddStringToObject(o, "server",
							b->serverAddress ? b->serverAddress : "");
	cJSON_AddNumberToObject(o, "server_port", b->serverPort);
	cJSON_AddStringToObject(o, "uuid", b->uuid ? b->uuid : "");
	cJSON_AddStringToObject(o, "tag", "proxy");
	cJSON_AddStringToObject(o, "type", "vless");
	if (b->flow && strlen(b->flow) &&
		strcmp(b->flow, "auto") != 0 &&
		strcmp(b->flow, "none") != 0) {
		cJSON_AddStringToObject(o, "flow", b->flow);
	}
	if (b->security && (strcmp(b->security, "tls") == 0 ||
						strcmp(b->security, "reality") == 0)) {
		cJSON* tls = cJSON_CreateObject();
		cJSON_AddBoolToObject(tls, "enabled", true);
		cJSON_AddBoolToObject(tls, "insecure", b->allowInsecure);
		if (b->sni && strlen(b->sni))
			cJSON_AddStringToObject(tls, "server_name", b->sni);
		if (b->alpn && strlen(b->alpn)) {
			cJSON* alpn_arr = cJSON_CreateArray();
			char* alpn_copy = strdup(b->alpn);
			char* p = alpn_copy;
			char* tok;
			while ((tok = strsep(&p, "\n")) != NULL) {
				if (!tok || !*tok) continue;
				cJSON_AddItemToArray(alpn_arr, cJSON_CreateString(tok));
			}
			free(alpn_copy);
			cJSON_AddItemToObject(tls, "alpn", alpn_arr);
		}
		if (b->utlsFingerprint && strlen(b->utlsFingerprint)) {
			cJSON* utls = cJSON_CreateObject();
			cJSON_AddBoolToObject(utls, "enabled", true);
			cJSON_AddStringToObject(utls, "fingerprint", b->utlsFingerprint);
			cJSON_AddItemToObject(tls, "utls", utls);
		}
		if (b->realityPubKey && strlen(b->realityPubKey)) {
			cJSON* reality = cJSON_CreateObject();
			cJSON_AddBoolToObject(reality, "enabled", true);
			cJSON_AddStringToObject(reality, "public_key", b->realityPubKey);
			cJSON_AddStringToObject(reality, "short_id",
									b->realityShortId ? b->realityShortId : "");
			cJSON_AddItemToObject(tls, "reality", reality);
		}
		cJSON_AddItemToObject(o, "tls", tls);
	}
	cJSON* trans = create_transport_object(b);
	if (trans) cJSON_AddItemToObject(o, "transport", trans);
	return o;
}

static cJSON* generate_vmess_obj(const Bean* b) {
	cJSON* o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "domain_strategy", "");
	cJSON_AddStringToObject(o, "server",
							b->serverAddress ? b->serverAddress : "");
	cJSON_AddNumberToObject(o, "server_port", b->serverPort);
	cJSON_AddStringToObject(o, "uuid", b->uuid ? b->uuid : "");
	cJSON_AddStringToObject(o, "security",
							(b->encryption && strlen(b->encryption) &&
							 strcmp(b->encryption, "auto") != 0)
								? b->encryption
								: "auto");
	cJSON_AddStringToObject(o, "tag", "proxy");
	cJSON_AddStringToObject(o, "type", "vmess");
	if (b->alterId != 0) cJSON_AddNumberToObject(o, "alter_id", b->alterId);
	if (b->packetEncoding == 1)
		cJSON_AddStringToObject(o, "packet_encoding", "packetaddr");
	else if (b->packetEncoding == 2)
		cJSON_AddStringToObject(o, "packet_encoding", "xudp");
	if (b->security && strcmp(b->security, "tls") == 0) {
		cJSON* tls = cJSON_CreateObject();
		cJSON_AddBoolToObject(tls, "enabled", true);
		cJSON_AddBoolToObject(tls, "insecure", b->allowInsecure);
		if (b->sni && strlen(b->sni))
			cJSON_AddStringToObject(tls, "server_name", b->sni);
		cJSON_AddItemToObject(o, "tls", tls);
	}
	cJSON* trans = create_transport_object(b);
	if (trans) cJSON_AddItemToObject(o, "transport", trans);
	return o;
}

static cJSON* generate_trojan_obj(const Bean* b) {
	cJSON* o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "domain_strategy", "");
	cJSON_AddStringToObject(o, "server",
							b->serverAddress ? b->serverAddress : "");
	cJSON_AddNumberToObject(o, "server_port", b->serverPort);
	cJSON_AddStringToObject(o, "password", b->password ? b->password : "");
	cJSON_AddStringToObject(o, "tag", "proxy");
	cJSON_AddStringToObject(o, "type", "trojan");
	if (b->security && strcmp(b->security, "tls") == 0) {
		cJSON* tls = cJSON_CreateObject();
		cJSON_AddBoolToObject(tls, "enabled", true);
		cJSON_AddBoolToObject(tls, "insecure", b->allowInsecure);
		if (b->sni && strlen(b->sni))
			cJSON_AddStringToObject(tls, "server_name", b->sni);
		if (b->alpn && strlen(b->alpn)) {
			cJSON* alpn_arr = cJSON_CreateArray();
			char* alpn_copy = strdup(b->alpn);
			char* p = alpn_copy;
			char* tok;
			while ((tok = strsep(&p, "\n")) != NULL) {
				if (!tok || !*tok) continue;
				cJSON_AddItemToArray(alpn_arr, cJSON_CreateString(tok));
			}
			free(alpn_copy);
			cJSON_AddItemToObject(tls, "alpn", alpn_arr);
		}
		if (b->utlsFingerprint && strlen(b->utlsFingerprint)) {
			cJSON* utls = cJSON_CreateObject();
			cJSON_AddBoolToObject(utls, "enabled", true);
			cJSON_AddStringToObject(utls, "fingerprint", b->utlsFingerprint);
			cJSON_AddItemToObject(tls, "utls", utls);
		}
		if (b->realityPubKey && strlen(b->realityPubKey)) {
			cJSON* reality = cJSON_CreateObject();
			cJSON_AddBoolToObject(reality, "enabled", true);
			cJSON_AddStringToObject(reality, "public_key", b->realityPubKey);
			cJSON_AddStringToObject(reality, "short_id",
									b->realityShortId ? b->realityShortId : "");
			cJSON_AddItemToObject(tls, "reality", reality);
		}
		cJSON_AddItemToObject(o, "tls", tls);
	}
	cJSON* trans = create_transport_object(b);
	if (trans) cJSON_AddItemToObject(o, "transport", trans);
	return o;
}

static cJSON* generate_shadowsocks_obj(const Bean* b) {
	cJSON* o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "server",
							b->serverAddress ? b->serverAddress : "");
	cJSON_AddNumberToObject(o, "server_port", b->serverPort);
	cJSON_AddStringToObject(o, "method", b->method ? b->method : "");
	cJSON_AddStringToObject(o, "password",
							b->ss_password ? b->ss_password : "");
	cJSON_AddStringToObject(o, "tag", "proxy");
	cJSON_AddStringToObject(o, "type", "shadowsocks");
	return o;
}

static cJSON* generate_socks_obj(const Bean* b) {
	cJSON* o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "server",
							b->serverAddress ? b->serverAddress : "");
	cJSON_AddNumberToObject(o, "server_port", b->serverPort);
	cJSON_AddStringToObject(o, "tag", "proxy");
	cJSON_AddStringToObject(o, "type", "socks");
	if (b->username && strlen(b->username))
		cJSON_AddStringToObject(o, "username", b->username);
	if (b->userpassword && strlen(b->userpassword))
		cJSON_AddStringToObject(o, "password", b->userpassword);
	return o;
}

static cJSON* generate_http_obj(const Bean* b) {
	cJSON* o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "server",
							b->serverAddress ? b->serverAddress : "");
	cJSON_AddNumberToObject(o, "server_port", b->serverPort);
	cJSON_AddStringToObject(o, "tag", "proxy");
	cJSON_AddStringToObject(o, "type", "http");
	if (b->username && strlen(b->username))
		cJSON_AddStringToObject(o, "username", b->username);
	if (b->userpassword && strlen(b->userpassword))
		cJSON_AddStringToObject(o, "password", b->userpassword);
	return o;
}

static cJSON* generate_outbound_obj(const Bean* b) {
	if (!b) return NULL;
	switch (b->kind) {
		case BEAN_VMESS_VLESS:
			if (b->alterId == -1) return generate_vless_obj(b);
			return generate_vmess_obj(b);
		case BEAN_TROJAN:
			return generate_trojan_obj(b);
		case BEAN_SHADOWSOCKS:
			return generate_shadowsocks_obj(b);
		case BEAN_SOCKS:
			return generate_socks_obj(b);
		case BEAN_HTTP:
			return generate_http_obj(b);
		default:
			return NULL;
	}
}

typedef struct {
	bool tun; // false
	bool proxy; // true
	int proxyport; // 2080
	bool fakeip; // false
	const char* dns_direct; // doh server ip addr
	int dns_default; // 0 - local, 1 - direct, 2 - remote
} ConfigOptions;

ConfigOptions* cfgopt_new() {
	ConfigOptions* b = (ConfigOptions*)calloc(1, sizeof(ConfigOptions));
	b->tun = false;
	b->proxy = true;
	b->proxyport = 2080;
	b->fakeip = false;
	b->dns_direct = "77.88.8.8"; // yandex
	b->dns_default = 1; // direct
	return b;
}

static char* generate_full_config_str(cJSON* outbound_obj, ConfigOptions* opt) {
	if (!outbound_obj) return NULL;
	cJSON* root = cJSON_CreateObject();

	/* log */
	cJSON* log = cJSON_CreateObject();
	cJSON_AddStringToObject(log, "level", "warning");
	cJSON_AddItemToObject(root, "log", log);

	/* dns */
	cJSON* dns = cJSON_CreateObject();
	switch (opt->dns_default) {
		case 0:
			cJSON_AddStringToObject(dns, "final", "dns-local");
			break;
		case 1:
			cJSON_AddStringToObject(dns, "final", "dns-direct");
			break;
		case 2:
			cJSON_AddStringToObject(dns, "final", "dns-remote");
			break;
	}
	cJSON_AddBoolToObject(dns, "independent_cache", true);
	cJSON_AddStringToObject(dns, "strategy", "ipv4_only");

	/* dns.rules (array) */
	cJSON* rules = cJSON_CreateArray();

	if(opt->fakeip) {
		cJSON* fakeip = cJSON_CreateObject();
		cJSON_AddBoolToObject(fakeip, "enabled", true);
		cJSON_AddStringToObject(fakeip, "inet4_range", "198.18.0.0/15");
		cJSON_AddStringToObject(fakeip, "inet6_range", "fc00::/18");
		cJSON_AddItemToObject(dns, "fakeip", fakeip);
		cJSON* r1 = cJSON_CreateObject();
		cJSON_AddBoolToObject(r1, "disable_cache", true);
		cJSON* inbound = cJSON_CreateArray();
		cJSON_AddItemToArray(inbound, cJSON_CreateString("tun-in"));
		cJSON_AddItemToObject(r1, "inbound", inbound);
		cJSON_AddStringToObject(r1, "server", "dns-fake");
		cJSON_AddItemToArray(rules, r1);
	}


	// cJSON* r0 = cJSON_CreateObject();
	// cJSON* doms = cJSON_CreateArray();
	// cJSON_AddItemToArray(doms, cJSON_CreateString("dns.google"));
	// cJSON_AddItemToObject(r0, "domain", doms);
	// cJSON_AddStringToObject(r0, "server", "dns-direct");
	// cJSON_AddItemToArray(rules, r0);

	cJSON_AddItemToObject(dns, "rules", rules);

	/* dns.servers */
	cJSON* servers = cJSON_CreateArray();
	cJSON* s_local = cJSON_CreateObject();
	cJSON_AddStringToObject(s_local, "type", "local");
	cJSON_AddStringToObject(s_local, "tag", "dns-local");
	cJSON_AddItemToArray(servers, s_local);
	cJSON* s_direct = cJSON_CreateObject();
	cJSON_AddStringToObject(s_direct, "type", "https");
	cJSON_AddStringToObject(s_direct, "server", opt->dns_direct);
	cJSON_AddNumberToObject(s_direct, "server_port", 443);
	cJSON_AddStringToObject(s_direct, "path", "/dns-query");
	cJSON_AddStringToObject(s_direct, "tag", "dns-direct");
	cJSON_AddItemToArray(servers, s_direct);
	cJSON* s_remote = cJSON_CreateObject();
	cJSON_AddStringToObject(s_remote, "type", "https");
	cJSON_AddStringToObject(s_remote, "server", "1.1.1.1"); // cloudflare
	cJSON_AddNumberToObject(s_remote, "server_port", 443);
	cJSON_AddStringToObject(s_remote, "path", "/dns-query");
	cJSON_AddStringToObject(s_remote, "detour", "proxy");
	cJSON_AddStringToObject(s_remote, "tag", "dns-remote");
	cJSON_AddItemToArray(servers, s_remote);

	if(opt->fakeip) {
		cJSON* s_fake = cJSON_CreateObject();
		cJSON_AddStringToObject(s_fake, "type", "fakeip");
		cJSON_AddStringToObject(s_fake, "tag", "dns-fake");
		cJSON_AddItemToArray(servers, s_fake);
	}
	cJSON_AddItemToObject(dns, "servers", servers);
	cJSON_AddItemToObject(root, "dns", dns);

	if(opt->tun || opt->proxy) {
		cJSON* inbounds = cJSON_CreateArray();
		if(opt->tun) {
			cJSON* tun = cJSON_CreateObject();
			cJSON_AddStringToObject(tun, "type", "tun");
			cJSON_AddStringToObject(tun, "tag", "tun-in");
			cJSON* addr_arr = cJSON_CreateArray();
			cJSON_AddItemToArray(addr_arr, cJSON_CreateString("172.19.0.1/28"));
			cJSON_AddItemToObject(tun, "address", addr_arr);
			cJSON_AddNumberToObject(tun, "mtu", 9000);
			cJSON_AddBoolToObject(tun, "auto_route", true);
			cJSON_AddBoolToObject(tun, "auto_redirect", true);
			cJSON_AddStringToObject(tun, "stack", "gvisor");
			cJSON_AddBoolToObject(tun, "endpoint_independent_nat", true);
			cJSON_AddBoolToObject(tun, "sniff", true);
			cJSON_AddBoolToObject(tun, "sniff_override_destination", false);
			cJSON_AddItemToArray(inbounds, tun);
		}
		if(opt->proxy) {
			cJSON* mixed = cJSON_CreateObject();
			cJSON_AddStringToObject(mixed, "type", "mixed");
			cJSON_AddStringToObject(mixed, "tag", "mixed-in");
			cJSON_AddStringToObject(mixed, "listen", "127.0.0.1");
			cJSON_AddNumberToObject(mixed, "listen_port", opt->proxyport);
			cJSON_AddBoolToObject(mixed, "sniff", true);
			cJSON_AddBoolToObject(mixed, "sniff_override_destination", false);
			cJSON_AddItemToArray(inbounds, mixed);
		}
		cJSON_AddItemToObject(root, "inbounds", inbounds);
	}

	cJSON* outbounds = cJSON_CreateArray();
	cJSON_AddItemToArray(
		outbounds,
		cJSON_Duplicate(outbound_obj, 1)
	);
	cJSON* direct = cJSON_CreateObject();
	cJSON_AddStringToObject(direct, "tag", "direct");
	cJSON_AddStringToObject(direct, "type", "direct");
	cJSON_AddItemToArray(outbounds, direct);
	cJSON_AddItemToObject(root, "outbounds", outbounds);

	/* route (same structure as original) */
	cJSON* route = cJSON_CreateObject();
	cJSON_AddBoolToObject(route, "auto_detect_interface", true);
	switch (opt->dns_default) {
		case 0:
			cJSON_AddStringToObject(route, "default_domain_resolver", "dns-local");
			break;
		case 1:
			cJSON_AddStringToObject(route, "default_domain_resolver", "dns-direct");
			break;
		case 2:
			cJSON_AddStringToObject(route, "default_domain_resolver", "dns-remote");
			break;
	}
	cJSON* rs = cJSON_CreateArray();
	cJSON_AddItemToObject(route, "rule_set", rs);
	cJSON* rr = cJSON_CreateArray();
	cJSON* rA = cJSON_CreateObject();
	cJSON* ports = cJSON_CreateArray();
	cJSON_AddItemToArray(ports, cJSON_CreateNumber(53));
	cJSON_AddItemToObject(rA, "port", ports);
	cJSON_AddStringToObject(rA, "action", "hijack-dns");
	cJSON_AddItemToArray(rr, rA);
	cJSON* rB = cJSON_CreateObject();
	cJSON* proto = cJSON_CreateArray();
	cJSON_AddItemToArray(proto, cJSON_CreateString("dns"));
	cJSON_AddItemToObject(rB, "protocol", proto);
	cJSON_AddStringToObject(rB, "action", "hijack-dns");
	cJSON_AddItemToArray(rr, rB);
	cJSON* rC = cJSON_CreateObject();
	cJSON* iparr = cJSON_CreateArray();
	cJSON_AddItemToArray(iparr, cJSON_CreateString("224.0.0.0/3"));
	cJSON_AddItemToArray(iparr, cJSON_CreateString("ff00::/8"));
	cJSON_AddItemToObject(rC, "ip_cidr", iparr);
	cJSON* siparr = cJSON_CreateArray();
	cJSON_AddItemToArray(siparr, cJSON_CreateString("224.0.0.0/3"));
	cJSON_AddItemToArray(siparr, cJSON_CreateString("ff00::/8"));
	cJSON_AddItemToObject(rC, "source_ip_cidr", siparr);
	cJSON_AddStringToObject(rC, "action", "reject");
	cJSON_AddItemToArray(rr, rC);
	cJSON_AddItemToObject(route, "rules", rr);
	cJSON_AddItemToObject(root, "route", route);

	char* out = cJSON_PrintUnformatted(root);
	char* fout = format_json(out);
	free(out);
	cJSON_Delete(root);
	return fout;
}
