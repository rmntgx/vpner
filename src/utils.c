#ifndef UTILS_C
#define UTILS_C

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>

static char* urldecode(const char* s) {
	if (!s) return NULL;
	size_t len = strlen(s);
	char* out = malloc(len + 1);
	if (!out) return NULL;
	size_t oi = 0;
	for (size_t i = 0; i < len; i++) {
		if (s[i] == '%' && i + 2 < len && isxdigit((unsigned char)s[i + 1]) &&
			isxdigit((unsigned char)s[i + 2])) {
			char hex[3] = {s[i + 1], s[i + 2], 0};
			out[oi++] = (char)strtol(hex, NULL, 16);
			i += 2;
		} else if (s[i] == '+')
			out[oi++] = ' ';
		else
			out[oi++] = s[i];
	}
	out[oi] = 0;
	return out;
}

static unsigned char* base64_decode(const char* data, size_t* out_len) {
	if (!data) return NULL;
	size_t len = strlen(data);
	int T[256];
	for (int i = 0; i < 256; i++) T[i] = -1;
	for (int i = 'A'; i <= 'Z'; i++) T[i] = i - 'A';
	for (int i = 'a'; i <= 'z'; i++) T[i] = 26 + (i - 'a');
	for (int i = '0'; i <= '9'; i++) T[i] = 52 + (i - '0');
	T[(unsigned char)'+'] = 62;
	T[(unsigned char)'/'] = 63;
	T[(unsigned char)'='] = 0;
	size_t outcap = (len * 3) / 4 + 4;
	unsigned char* out = malloc(outcap);
	if (!out) return NULL;
	size_t outi = 0;
	int val = 0, valb = -8;
	for (size_t i = 0; i < len; i++) {
		int c = (unsigned char)data[i];
		if (T[c] == -1) continue;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out[outi++] = (unsigned char)((val >> valb) & 0xFF);
			valb -= 8;
		}
	}
	if (out_len) *out_len = outi;
	return out;
}

static void trim_inplace(char* s) {
	if (!s) return;
	char* p = s;
	while (*p && isspace(*p)) p++;
	if (p != s) memmove(s, p, strlen(p) + 1);
	size_t l = strlen(s);
	while (l > 0 && isspace(s[l - 1])) s[--l] = 0;
}

char* file_readall(const char* path) {
	FILE* f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "❌ Error opening %s file\n", path);
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char* data = malloc(len + 1);
	if (!data) {
		fclose(f);
		return NULL;
	}
	size_t ret = fread(data, 1, len, f);
	fclose(f);
	if (ret != (size_t)len) {
		fprintf(stderr, "❌ Error reading %s file\n", path);
		free(data);
		return NULL;
	}
	data[len] = 0;
	return data;
}

#endif
