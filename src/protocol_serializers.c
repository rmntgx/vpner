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
