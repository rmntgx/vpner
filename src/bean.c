typedef enum {
	BEAN_UNKNOWN = 0,
	BEAN_VMESS_VLESS,
	BEAN_TROJAN,
	BEAN_SHADOWSOCKS,
	BEAN_SOCKS,
	BEAN_HTTP
} BeanKind;
typedef struct {
	BeanKind kind;
	char* serverAddress;
	int serverPort;
	char* name;
	char* type;
	char* security;
	char* sni;
	char* alpn;
	char* utlsFingerprint;
	bool allowInsecure;
	char* uuid;
	int alterId;
	char* flow;
	char* encryption;
	char* password;
	char* host;
	char* path;
	int wsMaxEarlyData;
	char* earlyDataHeaderName;
	int packetEncoding;
	char* realityPubKey;
	char* realityShortId;
	char* method;
	char* ss_password;
	char* username;
	char* userpassword;
	char* serviceName;
} Bean;

static Bean* bean_new(void) {
	Bean* b = (Bean*)calloc(1, sizeof(Bean));
	b->kind = BEAN_UNKNOWN;
	b->serverPort = 0;
	b->allowInsecure = false;
	b->alterId = 0;
	b->packetEncoding = 0;
	b->type = strdup("tcp");
	b->serviceName = NULL;
	return b;
}

static void bean_free(Bean* b) {
	if (!b) return;
#define FREE(x) \
	if (b->x) free(b->x);
	FREE(serverAddress);
	FREE(name);
	FREE(type);
	FREE(security);
	FREE(sni);
	FREE(alpn);
	FREE(utlsFingerprint);
	FREE(uuid);
	FREE(flow);
	FREE(encryption);
	FREE(password);
	FREE(host);
	FREE(path);
	FREE(realityPubKey);
	FREE(realityShortId);
	FREE(method);
	FREE(ss_password);
	FREE(username);
	FREE(userpassword);
	FREE(serviceName);
#undef FREE
	free(b);
}

/* --- Query -> bean --- */
static void apply_query_to_bean(Bean* b, const char* query) {
	if (!query) return;
	char* qcopy = strdup(query);
	char* p = qcopy;
	char* tok;

#define FREE(x) \
	if (b->x) free(b->x); \
	b->x = v ? v : strdup("");

	while ((tok = strsep(&p, "&")) != NULL) {
		if (!tok || !*tok) continue;
		char* eq = strchr(tok, '=');
		char *k = NULL, *v = NULL;
		if (eq) {
			*eq = 0;
			k = urldecode(tok);
			v = urldecode(eq + 1);
		} else {
			k = urldecode(tok);
			v = strdup("");
		}
		if (!k) continue;
		if (strcmp(k, "type") == 0) {
			free(b->type);
			b->type = v ? v : strdup("");
		} else if (strcmp(k, "security") == 0) {
			FREE(security);
		} else if (strcmp(k, "sni") == 0) {
			FREE(sni);
		} else if (strcmp(k, "alpn") == 0) {
			FREE(alpn);
		} else if (strcmp(k, "fp") == 0) {
			FREE(utlsFingerprint);
		} else if (strcmp(k, "allowInsecure") == 0) {
			if (v && (strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0)) b->allowInsecure = true;
			if (v) free(v);
		} else if (strcmp(k, "pbk") == 0) {
			FREE(realityPubKey);
		} else if (strcmp(k, "sid") == 0) {
			FREE(realityShortId);
		} else if (strcmp(k, "host") == 0) {
			FREE(host);
		} else if (strcmp(k, "path") == 0) {
			FREE(path);
		} else if (strcmp(k, "encryption") == 0) {
			FREE(encryption);
		} else if (strcmp(k, "flow") == 0) {
			FREE(flow);
		} else if (strcmp(k, "packetEncoding") == 0) {
			if (v) {
				if (strcmp(v, "packetaddr") == 0)
					b->packetEncoding = 1;
				else if (strcmp(v, "xudp") == 0)
					b->packetEncoding = 2;
				else
					b->packetEncoding = 0;
			}
			if (v) free(v);
		} else if (strcmp(k, "ed") == 0) {
			if (v) b->wsMaxEarlyData = atoi(v);
			if (v) free(v);
		} else if (strcmp(k, "eh") == 0) {
			FREE(earlyDataHeaderName);
		} else if (strcmp(k, "serviceName") == 0) {
			FREE(serviceName);
		} else {
			if (v) free(v);
		}
		free(k);
	}
	free(qcopy);
}
