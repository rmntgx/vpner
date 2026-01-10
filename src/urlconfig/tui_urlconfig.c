#include "bean.c"
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <readline/readline.h>
#include <readline/history.h>

#define URL_BUF_SIZE 16384
#define URL_FIELD_WIDTH 48
#define PORT_BUF_SIZE 16
#define PORT_FIELD_WIDTH 5

static int validate_url(const char *buf) {
    if (!buf || !buf[0]) return 0;
    Bean *b = parse_url(buf);
    if (!b) return 0;
    bean_free(b);
    return 1;
}

static bool validate_port(const char *buf) {
	int len = strlen(buf);
    if (len <= 0 || len > 5) return false;    
    unsigned long port = 0;
    for (int i = 0; i < len; ++i) {
        if (!isdigit((unsigned char)buf[i])) return false;
        port = port * 10 + (buf[i] - '0');
        if (port > 65535) return false;
    }
    return (port >= 1);
}

int tui_select_from_list(const char* title, const char** help, const char* options[], int count, int default_idx) {
    printf("\033[?25l"); // hide cursor

    int selected = default_idx;
    int menu_lines = 1 + (help ? 1 : 0) + count;

    // Draw loop
    while (1) {
        printf("\033[u"); // restore saved pos
		for (int i = 0; i < menu_lines; i++) printf("\033[K\n");
        printf("\033[%dA", menu_lines); // move back up
        printf("\033[33m[?] %s\033[0m\n", title);
        if (help) printf("\033[90m%s\033[0m\n", help[selected]);
        for (int i = 0; i < count; ++i) {
            if (i == selected) printf("\033[94m> %s\033[0m\n", options[i]);
            else printf("  %s\n", options[i]);
        }
        fflush(stdout);

        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) continue;
        if (c == '\n') break;
        if (c == 'k' || c == 'K') { selected = (selected - 1 + count) % count; continue; }
        if (c == 'j' || c == 'J') { selected = (selected + 1) % count; continue; }
        if (c == '\x1b') {
            char seq[2];
            if (read(STDIN_FILENO, &seq[0], 1) != 1) continue;
            if (read(STDIN_FILENO, &seq[1], 1) != 1) continue;
            if (seq[0] == '[') {
                if (seq[1] == 'A') selected = (selected - 1 + count) % count;
                else if (seq[1] == 'B') selected = (selected + 1) % count;
            }
        } else if (c == 'q' || c == '\x03') {
			return -1;
        }
    }
	printf("\033[u"); // restore saved pos
	for (int i = 0; i < menu_lines; i++) printf("\033[K\n");
	printf("\033[u"); // restore saved pos
    return selected;
}

static void tui_print_toggle_line(int selected, int index, const char *label, bool is_enabled) {
    const char *arrow = (selected == index) ? "> " : "  ";
    const char *status_color = is_enabled ? "\033[92m" : "\033[91m";  // green/red
    const char *status_text = is_enabled ? "On" : "Off";
    
    if (selected == index) printf("\033[94m");  // blue selection
    printf("%s%s: %s%s\033[0m\n", arrow, label, status_color, status_text);
    if (selected == index) printf("\033[0m");
}

static void tui_print_action_item(int selected, int index, const char *label, const char *color) {
    const char *arrow = (selected == index) ? "\033[94m> \033[0m\033[1m" : "  ";
    printf("%s%s%s\033[0m\n", arrow, color, label);
}

static void tui_print_editable_field(int selected, int index, const char *label,
                                const char *buf, int buf_len, int max_width,
                                bool is_valid) {
    const char *arrow = (selected == index) ? "> " : "  ";
    const char *colr = is_valid ? "\033[92m" : "\033[91m"; // green/red

    if (selected == index) printf("\033[94m"); // blue
    
    printf("%s%s: %s\033[4m", arrow, label, colr);
    
    int len = (buf_len < max_width) ? buf_len : max_width;
    for (int i = 0; i < len; ++i) putchar(buf[i]);
    for (int i = len; i < max_width; ++i) putchar(' ');
    
    printf("\033[0m\n");
}

static void tui_print_cfgopt_menu(ConfigOptions *opt, const char *urlbuf, int url_len,
                              const char *portbuf, int port_len, int selected) {
    printf("\033[33m[?] Create sing-box config:\033[0m\n");

    bool url_valid = validate_url(urlbuf);
    bool port_valid = validate_port(portbuf);

    tui_print_editable_field(selected, 0, "URL", urlbuf, url_len, URL_FIELD_WIDTH, url_valid);

    tui_print_toggle_line(selected, 1, "TUN", opt->tun);

    tui_print_toggle_line(selected, 2, "Proxy", opt->proxy);

    tui_print_editable_field(selected, 3, "Proxy port", portbuf, port_len, PORT_FIELD_WIDTH, port_valid);

    // tui_print_toggle_line(selected, 4, "Fake IP", opt->fakeip);

    /* DNS (direct) */
    {
        int dns_idx = 0;
        for (int i = 0; i < DNS_COUNT; ++i) {
            if (strcmp(opt->dns_direct, dns_values[i]) == 0) {
                dns_idx = i;
                break;
            }
        }
        
        const char *prefix = (selected == 4) ? "\033[94m> " : "  ";
        printf("%sDNS (direct): %s (%s)\033[0m\n", prefix, dns_names[dns_idx], dns_values[dns_idx]);
    }

    /* DNS Default Mode */
    {
        const char *mode_str = (opt->dns_default == 0) ? "local" :
                              (opt->dns_default == 1) ? "direct" : "remote";
        const char *prefix = (selected == 5) ? "\033[94m> " : "  ";
        printf("%sDNS default mode: %s\033[0m\n", prefix, mode_str);
    }

    tui_print_action_item(selected, 6, "Continue", "\033[92m"); // green
    tui_print_action_item(selected, 7, "Cancel", "\033[91m"); // red
}

static void tui_clear_menu_block(int menu_lines) {
    printf("\033[u"); /* restore saved pos */
	for (int i = 0; i < menu_lines; i++) printf("\033[K\n");
    printf("\033[u"); /* restore saved pos */
    fflush(stdout);
}

/**
	1 - state changed
	2 - save pressed
   -1 - cancel
*/
static int handle_get_cfgopt(int count, int *selected,
                               char *urlbuf, int *url_len, int *url_cursor,
                               char *portbuf, int *port_len, int *port_cursor,
                               ConfigOptions *opt, int menu_lines) {
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return 0;

    /* Escape sequences (arrows) */
    if (c == '\x1b') {
        char seq[2];
        if (read(STDIN_FILENO, &seq[0], 1) != 1) return 0;
        if (read(STDIN_FILENO, &seq[1], 1) != 1) return 0;
        if (seq[0] == '[') {
            switch (seq[1]) {
                case 'A':
                    if (*selected > 0) (*selected)--; else *selected = count - 1;
                    return 1;
                case 'B':
                    if (*selected < count - 1) (*selected)++; else *selected = 0;
                    return 1;
                case 'C':
                    if (*selected == 0) { if (*url_cursor < *url_len) (*url_cursor)++; }
                    else if (*selected == 3) { if (*port_cursor < *port_len) (*port_cursor)++; }
                    else if (*selected == 1) opt->tun = !opt->tun;
                    else if (*selected == 2) opt->proxy = !opt->proxy;
                    // else if (*selected == 4) opt->fakeip = !opt->fakeip;
                    else if (*selected == 4 || *selected == 5) {
						c = '\n';
						goto pass;
					}
                    return 1;
                case 'D':
                    if (*selected == 0) { if (*url_cursor > 0) (*url_cursor)--; }
                    else if (*selected == 3) { if (*port_cursor > 0) (*port_cursor)--; }
                    else if (*selected == 1) opt->tun = !opt->tun;
                    else if (*selected == 2) opt->proxy = !opt->proxy;
                    // else if (*selected == 4) opt->fakeip = !opt->fakeip;
                    return 1;
            }
        }
        return 0;
    }
	pass:
    /* Enter */
    if (c == '\n') {
        if (*selected == 6) {
            if (!validate_url(urlbuf)) { printf("\a"); return 1; }
            if (!validate_port(portbuf)) { printf("\a"); return 1; }
            return 2;
        } else if (*selected == 7) return -1;
        else if (*selected == 4) {
			tui_clear_menu_block(menu_lines);
			int cur_idx = 0, i;
			for (i = 0; i < DNS_COUNT; ++i) if (strcmp(opt->dns_direct, dns_values[i]) == 0) { cur_idx = i; break; }
			int idx = tui_select_from_list("Choose DNS (direct):", NULL, dns_names, DNS_COUNT, cur_idx);
			if(idx == -1) idx = 0;
			opt->dns_direct = dns_values[idx];
            return 1;
        } else if (*selected == 5) {
			tui_clear_menu_block(menu_lines);
			const char *dns_modes[] = {"local", "direct", "remote"};
			const char* helps[] ={
				"Your current DNS provider will be used",
				"DNS requests will not go through the proxy, but a custom proxy server will be used (recommended)",
				"DNS requests will go through a proxy to the Cloudflare DNS server"
			};
			int idx = tui_select_from_list("Choose default DNS mode:", helps, dns_modes, 3, opt->dns_default);
			if(idx == -1) idx = 0;
			opt->dns_default = idx;
            return 1;
        } else {
            if (*selected == 1) opt->tun = !opt->tun;
            else if (*selected == 2) opt->proxy = !opt->proxy;
            // else if (*selected == 4) opt->fakeip = !opt->fakeip;
            else { if (*selected < count - 1) (*selected)++; else *selected = 0; }
            return 1;
        }
    }

    /* Cancel */
	if (c == '\x03') return -1;

    if (*selected != 0) {
		if (c == 'q') return -1;
        if (c == 'k' || c == 'K') { if (*selected > 0) (*selected)--; else *selected = count - 1; return 1; }
        if (c == 'j' || c == 'J') { if (*selected < count - 1) (*selected)++; else *selected = 0; return 1; }
    }

    /* Inline editing */
    if (*selected == 0) {
        /* URL edit: backspace or insert at cursor */
        if (c == 127 || c == '\b') {
            if (*url_cursor > 0 && *url_len > 0) {
                memmove(&urlbuf[*url_cursor - 1], &urlbuf[*url_cursor], (*url_len) - (*url_cursor) + 1);
                (*url_cursor)--; (*url_len)--;
            }
            return 1;
        } else if (isprint((unsigned char)c) && *url_len < URL_BUF_SIZE - 1) {
            memmove(&urlbuf[*url_cursor + 1], &urlbuf[*url_cursor], (*url_len) - (*url_cursor) + 1);
            urlbuf[*url_cursor] = c;
            (*url_cursor)++; (*url_len)++;
            return 1;
        }
    } else if (*selected == 3) {
        /* port inline: digits and backspace */
        if (c == 127 || c == '\b') {
            if (*port_cursor > 0 && *port_len > 0) {
                memmove(&portbuf[*port_cursor - 1], &portbuf[*port_cursor], (*port_len) - (*port_cursor) + 1);
                (*port_cursor)--; (*port_len)--;
            }
            int v = atoi(portbuf);
            if (v >= 1 && v <= 65535) opt->proxyport = v;
            return 1;
        } else if (c >= '0' && c <= '9' && *port_len < PORT_FIELD_WIDTH) {
            memmove(&portbuf[*port_cursor + 1], &portbuf[*port_cursor], (*port_len) - (*port_cursor) + 1);
            portbuf[*port_cursor] = c;
            (*port_cursor)++; (*port_len)++;
            int v = atoi(portbuf);
            if (v >= 1 && v <= 65535) opt->proxyport = v;
            return 1;
        }
    }

    return 0;
}

ConfigOptions* tui_get_cfgopt(char **out_url) {
    if (out_url) *out_url = NULL;

    ConfigOptions *opt = malloc(sizeof(ConfigOptions));
    opt->tun = false;
    opt->proxy = true;
    opt->proxyport = 2080;
    opt->fakeip = false;
    opt->dns_direct = dns_values[0];
    opt->dns_default = 1;

    /* buffers */
    static char urlbuf[URL_BUF_SIZE];
    int url_len = 0;
    int url_cursor = 0;
    memset(urlbuf, 0, sizeof(urlbuf));

    char portbuf[PORT_BUF_SIZE];
    snprintf(portbuf, sizeof(portbuf), "%d", opt->proxyport);
    int port_len = strlen(portbuf);
    int port_cursor = port_len;

    int selected = 0;
    int items = 8; /* URL, TUN, Proxy, ProxyPort, DNS direct, DNS mode, Save, Cancel */
    int menu_lines = 1 + items;

    /* Prepare terminal */
    enable_raw_mode();
    printf("\033[?25l"); /* hide cursor */
	printf("\033[s");

    tui_print_cfgopt_menu(opt, urlbuf, url_len, portbuf, port_len, selected);
    fflush(stdout);

    int result = 0;
    while (1) {
    int r = handle_get_cfgopt(items, &selected,
                                urlbuf, &url_len, &url_cursor,
                                portbuf, &port_len, &port_cursor,
                                opt, menu_lines);
        if (r == 1) { // redraw
            printf("\033[u");
			for (int i = 0; i < menu_lines; ++i) printf("\033[K\n");
            printf("\033[u");

            tui_print_cfgopt_menu(opt, urlbuf, url_len, portbuf, port_len, selected);

            fflush(stdout);
        } else if (r == 2 || r == -1) { // save
            result = r;
            break;
        }
    }

	printf("\033[u");
	for (int i = 0; i < menu_lines; i++) printf("\033[K\n");
	printf("\033[u");
	printf("\033[?25h");
    if (result == 2) {
        if (out_url) *out_url = strdup(urlbuf);
        return opt;
    } else { // cancel
		free(opt);
		if (out_url) *out_url = NULL;
        return NULL;
    }
}

void launch_urlconfig_tui() {
	printf("\033[s");
	const char* opts[] = {
		"New full config",
		"Update outbound"
	};
	const char* helps[] = {
		"A new config file will be created",
		"Outbound in the existing config will be replaced"
	};

	enable_raw_mode();
	int idx = tui_select_from_list("Config mode", helps, opts, 2, 0);
	if(idx == -1) {
		printf("\033[u");
		printf("\033[?25h");
		fprintf(stderr, "❌ Creation cancelled\n");
		disable_raw_mode();
		exit(1);
	}
	if(idx == 0) {
		char* url = NULL;
		ConfigOptions* cfgopt = tui_get_cfgopt(&url);
		if (!cfgopt) { 
			printf("\033[u");
			printf("\033[?25h");
			disable_raw_mode();
			printf("❌ Creation cancelled\n");
			exit(1);
		}

		Bean* b = parse_url(url);
		if (!b) {
			printf("\033[u");
			printf("\033[?25h");
			disable_raw_mode();
			fprintf(stderr, "❌ Invalid URL\n");
			exit(2);
		}

		cJSON* outbound_obj = generate_outbound_obj(b);
		if (!outbound_obj) { 
			printf("\033[u");
			printf("\033[?25h");
			disable_raw_mode();
			fprintf(stderr, "❌ Failed to generate outbound\n"); 
			exit(3);
		}

		char* full = generate_full_config_str(outbound_obj, cfgopt);
		if (!full) {
			printf("\033[u");
			printf("\033[?25h");
			disable_raw_mode();
			fprintf(stderr, "❌ Failed to generate full config\n");
			exit(4);
		}

		int cnt_cfg;
		char** cfgs = get_configs_paths(&cnt_cfg);
		char** options = malloc((cnt_cfg + 1) * sizeof(char*));
		for(int i = 0; i < cnt_cfg; i++) options[i + 1] = cfgs[i];
		options[0] = strdup("New");

		int idx = tui_select_from_list("Select folder", NULL, (const char**)options, cnt_cfg + 1, 0);
		if(idx == -1) idx = 0;

		printf("\033[u");
		printf("\033[?25h");
		disable_raw_mode();

		char* path;
		if(idx == 0) {
			path = readline("\033[92mFull path to the new file: \033[0m");
		} else {
			char *name = readline("\033[92mFile name: \033[0m");
			path = malloc(PATH_MAX);
			strcpy(path, options[idx]);
			strcat(path, "/");
			strcat(path, name);
		}

		bool suc = new_conffile(path, full);

		if(suc) {
			printf("\033[92mConfig has been successfully created\033[0m\n");
		} else {
			fprintf(stderr, "\033[91mFatal errors occurred while creating the config\033[0m\n");
		}

		for(int i = 0; i <= cnt_cfg; i++) free(options[i]);
		free(options);
		free(cfgs);
		free(path);
		// printf("\n\033[92mGenerated sing-box config:\033[0m\n%s\n", full);
	} else {
		printf("\033[u");
		printf("\033[?25h");
		disable_raw_mode();

		char* urlbuf = NULL;
		Bean* b = NULL;
		while(!b) {
			char *urlbuf = readline("\033[92mURL: \033[0m");
			if (!urlbuf || !urlbuf[0]) {
				b = NULL;
			} else {
				b = parse_url(urlbuf);
			}
			if (!b) fprintf(stderr, "❌ Invalid URL\n");
		}
		cJSON* outbound_obj = generate_outbound_obj(b);
		if (!outbound_obj) { fprintf(stderr, "❌ Failed to generate outbound\n"); exit(3); }

		size_t cfg_cnt;
		Config* cfgs = load_configs(&cfg_cnt);
		if(!cfgs || cfg_cnt == 0) {
			fprintf(stderr, "❌ No configs for modification\n");
			exit(1);
		}
		const char** menuitems = malloc(cfg_cnt * sizeof(char*));
		for(size_t i = 0; i < cfg_cnt; i++) menuitems[i] = cfgs[i].name;
		const char** menuhelps = malloc(cfg_cnt * sizeof(char*));
		for(size_t i = 0; i < cfg_cnt; i++) menuhelps[i] = cfgs[i].path;

		printf("\033[u"); // restore
		printf("\033[J"); // clear below

		enable_raw_mode();
		int idx = tui_select_from_list("Config for modification", menuhelps, menuitems, cfg_cnt, 0);
		if(idx == -1) {
			printf("\033[u");
			printf("\033[?25h");
			fprintf(stderr, "❌ Creation cancelled\n");
			disable_raw_mode();
			exit(1);
		}
		disable_raw_mode();
		printf("\033[u");
		printf("\033[?25h");

		for(size_t i = 0; i < cfg_cnt; i++) free(cfgs[i].name);
		free(menuitems);
		free(menuhelps);
		if(urlbuf) free(urlbuf);

		bool suc = modify_config(outbound_obj, cfgs[idx].path);

		if(suc) {
			printf("\033[92mConfig has been successfully modified\033[0m\n");
		} else {
			fprintf(stderr, "\033[91mFatal errors occurred while modifying the config\033[0m\n");
		}

		free(cfgs);
	}
}
