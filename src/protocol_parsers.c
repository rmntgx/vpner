static Bean* parse_v2ray(const char* link) {
	Bean* b = bean_new();
	if (strncmp(link, "vless://", 8) == 0) {
		b->kind = BEAN_VMESS_VLESS;
		b->alterId = -1;
	} else {
		b->kind = BEAN_VMESS_VLESS;
		b->alterId = 0;
	}
	const char* p = strstr(link, "://");
	if (!p) {
		bean_free(b);
		return NULL;
	}
	p += 3;
	const char* hash = strchr(p, '#');
	const char* quest = strchr(p, '?');
	const char* at = strchr(p, '@');
	if (!at) {
		bean_free(b);
		return NULL;
	}
	size_t userlen = (size_t)(at - p);
	char* user = malloc(userlen + 1);
	memcpy(user, p, userlen);
	user[userlen] = 0;
	char* user_dec = urldecode(user);
	free(user);
	if (user_dec) trim_inplace(user_dec);
	const char* hoststart = at + 1;
	const char* hostend = hoststart;
	while (*hostend && *hostend != ':' && *hostend != '?' && *hostend != '#')
		hostend++;
	size_t hostlen = (size_t)(hostend - hoststart);
	char* host = malloc(hostlen + 1);
	memcpy(host, hoststart, hostlen);
	host[hostlen] = 0;
	int port = 0;
	if (*hostend == ':') {
		const char* portstart = hostend + 1;
		const char* portend = portstart;
		while (*portend && *portend != '?' && *portend != '#')
			portend++;
		size_t portlen = (size_t)(portend - portstart);
		char* portstr = malloc(portlen + 1);
		memcpy(portstr, portstart, portlen);
		portstr[portlen] = 0;
		port = atoi(portstr);
		free(portstr);
	}
	b->serverAddress = strdup(host);
	b->serverPort = port;
	free(host);
	b->uuid = user_dec ? user_dec : strdup("");
	if (hash) {
		char* frag = urldecode(hash + 1);
		if (frag) {
			trim_inplace(frag);
			b->name = frag;
		}
	}
	if (quest) {
		const char* qstart = quest + 1;
		const char* qend = hash ? hash : (link + strlen(link));
		size_t qlen = (size_t)(qend - qstart);
		char* qcopy = malloc(qlen + 1);
		memcpy(qcopy, qstart, qlen);
		qcopy[qlen] = 0;
		apply_query_to_bean(b, qcopy);
		free(qcopy);
	}
	return b;
}

static Bean* parse_trojan(const char* link) {
	Bean* b = bean_new();
	b->kind = BEAN_TROJAN;
	const char* p = strstr(link, "://");
	if (!p) {
		bean_free(b);
		return NULL;
	}
	p += 3;
	const char* at = strchr(p, '@');
	if (!at) {
		bean_free(b);
		return NULL;
	}
	size_t passlen = (size_t)(at - p);
	char* pass = malloc(passlen + 1);
	memcpy(pass, p, passlen);
	pass[passlen] = 0;
	char* pass_dec = urldecode(pass);
	free(pass);
	b->password = pass_dec ? pass_dec : strdup("");
	const char* hoststart = at + 1;
	const char* hostend = hoststart;
	while (*hostend && *hostend != ':' && *hostend != '?' && *hostend != '#')
		hostend++;
	size_t hostlen = (size_t)(hostend - hoststart);
	char* host = malloc(hostlen + 1);
	memcpy(host, hoststart, hostlen);
	host[hostlen] = 0;
	int port = 0;
	if (*hostend == ':') {
		const char* portstart = hostend + 1;
		const char* portend = portstart;
		while (*portend && *portend != '?' && *portend != '#')
			portend++;
		size_t portlen = (size_t)(portend - portstart);
		char* portstr = malloc(portlen + 1);
		memcpy(portstr, portstart, portlen);
		portstr[portlen] = 0;
		port = atoi(portstr);
		free(portstr);
	}
	b->serverAddress = strdup(host);
	b->serverPort = port;
	free(host);
	const char* hash = strchr(p, '#');
	const char* quest = strchr(p, '?');
	if (hash) {
		char* frag = urldecode(hash + 1);
		if (frag) b->name = frag;
	}
	if (quest) {
		const char* qstart = quest + 1;
		const char* qend = hash ? hash : (link + strlen(link));
		size_t qlen = (size_t)(qend - qstart);
		char* qcopy = malloc(qlen + 1);
		memcpy(qcopy, qstart, qlen);
		qcopy[qlen] = 0;
		apply_query_to_bean(b, qcopy);
		free(qcopy);
	}
	return b;
}

static Bean* parse_shadowsocks(const char* link) {
	Bean* b = bean_new();
	b->kind = BEAN_SHADOWSOCKS;
	const char* p = strstr(link, "://");
	if (!p) {
		bean_free(b);
		return NULL;
	}
	p += 3;
	const char* hash = strchr(p, '#');
	if (hash) {
		char* frag = urldecode(hash + 1);
		if (frag) b->name = frag;
	}
	const char* at = strchr(p, '@');
	if (!at) {
		bean_free(b);
		return NULL;
	}
	size_t credlen = (size_t)(at - p);
	char* cred = malloc(credlen + 1);
	memcpy(cred, p, credlen);
	cred[credlen] = 0;
	bool is_base64 = true;
	for (size_t i = 0; i < credlen; i++) {
		char c = cred[i];
		if (!(isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=')) {
			is_base64 = false;
			break;
		}
	}
	if (is_base64) {
		size_t outl = 0;
		unsigned char* decoded = base64_decode(cred, &outl);
		if (decoded && outl > 0) {
			char* dec_str = malloc(outl + 1);
			memcpy(dec_str, decoded, outl);
			dec_str[outl] = 0;
			free(decoded);
			char* colon = strchr(dec_str, ':');
			if (colon) {
				*colon = 0;
				b->method = strdup(dec_str);
				b->ss_password = strdup(colon + 1);
			} else {
				b->method = dec_str;
				b->ss_password = strdup("");
			}
			if (colon) free(dec_str); /* dec_str either moved or kept */
		} else {
			free(cred);
			bean_free(b);
			return NULL;
		}
	} else {
		char* decoded = urldecode(cred);
		char* colon = strchr(decoded, ':');
		if (colon) {
			*colon = 0;
			b->method = strdup(decoded);
			b->ss_password = strdup(colon + 1);
		} else {
			b->method = decoded;
			b->ss_password = strdup("");
		}
		if (colon) free(decoded);
	}
	free(cred);
	const char* hoststart = strchr(p, '@') + 1;
	const char* hostend = hoststart;
	while (*hostend && *hostend != ':' && *hostend != '#')
		hostend++;
	size_t hostlen = (size_t)(hostend - hoststart);
	char* host = malloc(hostlen + 1);
	memcpy(host, hoststart, hostlen);
	host[hostlen] = 0;
	int port = 0;
	if (*hostend == ':') {
		const char* ps = hostend + 1;
		const char* pe = ps;
		while (*pe && *pe != '#')
			pe++;
		size_t portlen = (size_t)(pe - ps);
		char* portstr = malloc(portlen + 1);
		memcpy(portstr, ps, portlen);
		portstr[portlen] = 0;
		port = atoi(portstr);
		free(portstr);
	}
	b->serverAddress = strdup(host);
	b->serverPort = port;
	free(host);
	return b;
}

static Bean* parse_socks(const char* link) {
	Bean* b = bean_new();
	b->kind = BEAN_SOCKS;
	const char* p = strstr(link, "://");
	if (!p) {
		bean_free(b);
		return NULL;
	}
	p += 3;
	const char* hash = strchr(p, '#');
	if (hash) {
		char* frag = urldecode(hash + 1);
		if (frag) b->name = frag;
	}
	const char* at = strchr(p, '@');
	if (at) {
		size_t credlen = (size_t)(at - p);
		char* cred = malloc(credlen + 1);
		memcpy(cred, p, credlen);
		cred[credlen] = 0;
		char* dec = urldecode(cred);
		free(cred);
		char* colon = strchr(dec, ':');
		if (colon) {
			*colon = 0;
			b->username = strdup(dec);
			b->userpassword = strdup(colon + 1);
		} else
			b->username = strdup(dec);
		free(dec);
		p = at + 1;
	}
	const char* hostend = p;
	while (*hostend && *hostend != ':' && *hostend != '#')
		hostend++;
	size_t hostlen = (size_t)(hostend - p);
	char* host = malloc(hostlen + 1);
	memcpy(host, p, hostlen);
	host[hostlen] = 0;
	int port = 0;
	if (*hostend == ':') {
		const char* ps = hostend + 1;
		const char* pe = ps;
		while (*pe && *pe != '#')
			pe++;
		size_t portlen = (size_t)(pe - ps);
		char* portstr = malloc(portlen + 1);
		memcpy(portstr, ps, portlen);
		portstr[portlen] = 0;
		port = atoi(portstr);
		free(portstr);
	}
	b->serverAddress = strdup(host);
	b->serverPort = port;
	free(host);
	return b;
}

static Bean* parse_http(const char* link) {
	Bean* b = bean_new();
	b->kind = BEAN_HTTP;
	const char* p = strstr(link, "://");
	if (!p) {
		bean_free(b);
		return NULL;
	}
	p += 3;
	const char* hash = strchr(p, '#');
	if (hash) {
		char* frag = urldecode(hash + 1);
		if (frag) b->name = frag;
	}
	const char* at = strchr(p, '@');
	if (at) {
		size_t credlen = (size_t)(at - p);
		char* cred = malloc(credlen + 1);
		memcpy(cred, p, credlen);
		cred[credlen] = 0;
		char* dec = urldecode(cred);
		free(cred);
		char* colon = strchr(dec, ':');
		if (colon) {
			*colon = 0;
			b->username = strdup(dec);
			b->userpassword = strdup(colon + 1);
		} else
			b->username = strdup(dec);
		free(dec);
		p = at + 1;
	}
	const char* hostend = p;
	while (*hostend && *hostend != ':' && *hostend != '#')
		hostend++;
	size_t hostlen = (size_t)(hostend - p);
	char* host = malloc(hostlen + 1);
	memcpy(host, p, hostlen);
	host[hostlen] = 0;
	int port = 0;
	if (*hostend == ':') {
		const char* ps = hostend + 1;
		const char* pe = ps;
		while (*pe && *pe != '#')
			pe++;
		size_t portlen = (size_t)(pe - ps);
		char* portstr = malloc(portlen + 1);
		memcpy(portstr, ps, portlen);
		portstr[portlen] = 0;
		port = atoi(portstr);
		free(portstr);
	}
	b->serverAddress = strdup(host);
	b->serverPort = port;
	free(host);
	return b;
}

static Bean* parse_url(const char* url) {
	if (!url) return NULL;
	if (strncmp(url, "vless://", 8) == 0 || strncmp(url, "vmess://", 8) == 0)
		return parse_v2ray(url);
	if (strncmp(url, "trojan://", 9) == 0) return parse_trojan(url);
	if (strncmp(url, "ss://", 5) == 0) return parse_shadowsocks(url);
	if (strncmp(url, "socks://", 8) == 0 || strncmp(url, "socks4://", 9) == 0 ||
		strncmp(url, "socks4a://", 10) == 0 ||
		strncmp(url, "socks5://", 9) == 0)
		return parse_socks(url);
	if (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0)
		return parse_http(url);
	return NULL;
}
