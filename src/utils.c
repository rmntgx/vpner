#ifndef UTILS_C
#define UTILS_C

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <termios.h>

struct termios orig_termios;

void disable_raw_mode() {
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode() {
	atexit(disable_raw_mode);
	fflush(stdout);
	tcflush(STDIN_FILENO, TCIFLUSH);
	struct termios raw = orig_termios;
	raw.c_lflag &= ~(ECHO | ICANON | ISIG); // Disable signal processing
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

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

char* file_readall(const char* path, bool quite) {
	FILE* f = fopen(path, "r");
	if (!f) {
		if(!quite) fprintf(stderr, "❌ Error opening %s file\n", path);
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
		if(!quite) fprintf(stderr, "❌ Error reading %s file\n", path);
		free(data);
		return NULL;
	}
	data[len] = 0;
	return data;
}

char* format_json(const char* input) {
    size_t len = strlen(input);
    size_t capacity = len * 2 + 100;
    char* out = malloc(capacity);
    if (!out) return NULL;
    
    size_t pos = 0;
    int indent = 0, in_str = 0, esc = 0;

    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (pos + 32 >= capacity) {
            capacity *= 2;
            char* tmp = realloc(out, capacity);
            if (!tmp) { free(out); return NULL; }
            out = tmp;
        }

        if (in_str) {
            out[pos++] = c;
            if (esc) esc = 0;
            else if (c == '\\') esc = 1;
            else if (c == '"') in_str = 0;
            continue;
        }

        switch (c) {
			case '"':
				in_str = 1;
				esc = 0;
				out[pos++] = c;
				break;
			case '{': case '[':
				out[pos++] = c;
				out[pos++] = '\n';
				indent++;
				for (int j = 0; j < indent * 2; j++) out[pos++] = ' ';
				break;
			case '}': case ']':
				out[pos++] = '\n';
				if (indent) indent--;
				for (int j = 0; j < indent * 2; j++) out[pos++] = ' ';
				out[pos++] = c;
				break;
			case ':':
				out[pos++] = c;
				out[pos++] = ' ';
				break;
			case ',':
				out[pos++] = c;
				out[pos++] = '\n';
				for (int j = 0; j < indent * 2; j++) out[pos++] = ' ';
				break;
			default:
				if (!isspace((unsigned char)c)) out[pos++] = c;
        }
    }
    out[pos] = '\0';
    return out;
}

#endif
