#include <fcntl.h>
#include <limits.h>
#include <linux/limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "cjson/cJSON.h"
#include "config_load.c"
#include "help.h"
#include "create_tui.c"
#include <readline/readline.h>
#include <readline/history.h>

#define STATE_FILE "/tmp/.vpner_state.json"

typedef struct {
	int pid;
	char* config;
} State;


// TUI functions
void print_menu(Config* configs, int count, int selected) {
	printf("\033[33m[?] Select configuration:\033[0m\n");
	for (int i = 0; i < count; i++) {
		if (i == selected) {
			printf("\033[94m> %s\033[0m\n", configs[i].name);
		} else {
			printf("  %s\n", configs[i].name);
		}
	}
}

int handle_input(int count, int* selected) {
	char c;
	while (read(STDIN_FILENO, &c, 1) == 1) {
		if (c == '\x1b') {
			char seq[2];
			if (read(STDIN_FILENO, &seq[0], 1) != 1) return 0;
			if (read(STDIN_FILENO, &seq[1], 1) != 1) return 0;
			if (seq[0] == '[') {
				switch (seq[1]) {
					case 'A': // Up
						if (*selected > 0) (*selected)--;
						else (*selected) = count - 1;
						return 1;
					case 'B': // Down
						if (*selected < count - 1) (*selected)++;
						else (*selected) = 0;
						return 1;
				}
			}
		} else if (c == '\n') {
			return 2;
		} else if (c == 'q' || c == '\x03') {
			return -1;
		} else if (c == 'k' || c == 'K') {
			if (*selected > 0) (*selected)--;
			else (*selected) = count - 1;
			return 1;
		} else if (c == 'j' || c == 'J') {
			if (*selected < count - 1) (*selected)++;
			else (*selected) = 0;
			return 1;
		}
	}
	return 0;
}

int show_menu(Config* configs, int count) {
	if(!isatty(STDIN_FILENO)) {
			fprintf(stderr, "Run me in terminal\n");
			return -1;
	}
	enable_raw_mode();
	printf("\033[?25l"); // Hide cursor
	int selected = 0;
	int result = -1;
	int menu_lines = count + 1; // Header + items

	// Initial draw
	print_menu(configs, count, selected);

	// Move cursor to menu start position and save
	printf("\033[%dA", menu_lines);
	printf("\033[s");

	while (1) {
		int r = handle_input(count, &selected);
		if (r == 1) {
			// Redraw menu at saved position
			printf("\033[u");
			print_menu(configs, count, selected);
			printf("\033[u");
			fflush(stdout);
		} else if (r == 2 || r == -1) {
			result = (r == 2) ? selected : -1;
			break;
		}
	}

	// Clear menu area on exit
	printf("\033[u");
	for (int i = 0; i < menu_lines; i++) printf("\033[K\n");
	printf("\033[u");

	printf("\033[?25h"); // Show cursor
	disable_raw_mode();
	return result;
}


// State handling
State read_state() {
	State state = {0};
	FILE* f = fopen(STATE_FILE, "r");
	if (!f) return state;

	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char* data = malloc(len + 1);
	if (!data) {
		fclose(f);
		return state;
	}
	size_t ret = fread(data, 1, len, f);
	fclose(f);
	if (ret != (size_t)len) {
		fprintf(stderr, "❌ Reading error opening state file\n");
		free(data);
		return state;
	}
	data[len] = 0;

	cJSON* root = cJSON_Parse(data);
	free(data);
	if (!root) return state;
	if (!cJSON_IsObject(root)) return state;

	cJSON* piditem = cJSON_GetObjectItem(root, "pid");
	if (!cJSON_IsNumber(piditem)) return state;
	cJSON* config = cJSON_GetObjectItem(root, "config");
	if (!cJSON_IsString(config)) return state;
	state.config = config ? strdup(config->valuestring) : NULL;
	state.pid = piditem->valueint;

	cJSON_Delete(root);
	return state;
}

void write_state(pid_t pid, const char* config) {
	cJSON* root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "pid", pid);
	cJSON_AddStringToObject(root, "config", config);

	char* data = cJSON_Print(root);
	mode_t old_umask = umask(0);
	int fd = open(STATE_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	umask(old_umask);
	if(fd >= 0) {
		FILE* f = fdopen(fd, "w");
		if (f) {
			fputs(data, f);
			fclose(f);
		}
	}
	free(data);
	cJSON_Delete(root);
}

void kill_previous_process() {
	State state = read_state();
	if (state.pid == 0) return;
	// Check if process exists
	bool process_exists = (getpgid(state.pid) >= 0);
	bool process_killable = (kill(state.pid, 0) == 0);
	if (process_exists) {
		if(process_killable) {
			printf("🔁 Stopping previous process (PID: %d)\n", state.pid);
			kill(state.pid, SIGTERM);
		} else { // run from root
			char self_path[4096];
			ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
			if (len == -1) {
				perror("❌ Failed to resolve /proc/self/exe");
				return;
			}
			self_path[len] = '\0';
            char* args[] = {"pkexec", self_path, "--stop", NULL};
            exit(execvp("pkexec", args));
		}
	} else {
		printf("⚠️ Previous process not running\n");
	}

	remove(STATE_FILE);
	free(state.config);
}

void run_singbox_in_fork(const char* config_path) {
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);

        char* args[] = {"sing-box", "run", "-c", (char*)config_path, NULL};
        execvp("sing-box", args);
        perror("❌ exec failed");
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        write_state(pid, config_path);
        printf("✅ sing-box started with PID: %d\n", pid);
        exit(EXIT_SUCCESS);
    } else {
        perror("❌ Fork failed");
        exit(EXIT_FAILURE);
    }
}

void start_singbox(const char* config_path, bool run_as_root) {
	if (run_as_root) {
        pid_t pid = fork();
        if (pid == 0) {
			char self_path[4096];
			ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
			if (len == -1) {
				perror("❌ Failed to resolve /proc/self/exe");
				return;
			}
			self_path[len] = '\0';
            char* args[] = {"pkexec", self_path, "--run-root-internal", (char*)config_path, NULL};
            execvp("pkexec", args);
            perror("❌ Failed to exec pkexec");
            exit(EXIT_FAILURE);
        } else if (pid > 0) {
            printf("🔐 Waiting for pkexec...\n");
            waitpid(pid, NULL, 0);
            printf("✅ pkexec process complete\n");
        } else {
            perror("❌ Fork failed");
        }
        return;
    }
	
	run_singbox_in_fork(config_path);
}

int parse_args(int argc, char* argv[]) {
	if (argc >= 3 && strcmp(argv[1], "--run-root-internal") == 0) {
        run_singbox_in_fork(argv[2]);
        exit(0);
    }
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] != '-') break;

		size_t stlen = strlen(argv[i]);
		bool fullnum = true;
		for (size_t y = 1; y < stlen; y++) {
			if (!(argv[i][y] >= '0' && argv[i][y] <= '9')) {
				fullnum = false;
				break;
			}
		}
		if (fullnum) {
			return atoi(argv[i] + 1);
		} else if (strcmp(argv[i], "--help") == 0) {
			printf(HELP_TEXT); // Use the help text above
			exit(0);
		} else if (strcmp(argv[i], "--stop") == 0) {
			kill_previous_process();
			exit(0);
		} else if (strcmp(argv[i], "--status") == 0) {
			State state = read_state();
			if (state.pid && kill(state.pid, 0) == 0) {
				printf("VPN running (PID: %d, Config: %s)\n", state.pid,
					   state.config);
			} else {
				printf("No VPN running\n");
			}
			exit(0);
		} else if (strcmp(argv[i], "--list") == 0) {
			size_t count;
			Config* configs = load_configs(&count);
			for (size_t i = 0; i < count; i++) {
				printf("%s (%s)\n", configs[i].name, configs[i].path);
			}
			exit(0);
		} else if (strcmp(argv[i], "--list-rofi") == 0) {
			size_t count;
			Config* configs = load_configs(&count);
			State state = read_state();
			if (state.pid && kill(state.pid, 0) == 0) {
				for (size_t i = 0; i < count; i++) {
					if (strcmp(configs[i].path, state.config) == 0)
						printf("✔️ %s\n", configs[i].name);
					else
						printf("%i) %s\n", (int)i + 1, configs[i].name);
				}
			} else {
				for (size_t i = 0; i < count; i++) {
					printf("%i) %s\n", (int)i + 1, configs[i].name);
				}
			}
			exit(0);
		} else if (strcmp(argv[i], "--create") == 0 || strcmp(argv[i], "-c") == 0) {
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
				ConfigOptions* cfgopt = create_cfgopt(&url);
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

			exit(0);
		}
	}
	return -1;
}

int main(int argc, char* argv[]) {
	tcgetattr(STDIN_FILENO, &orig_termios);
	printf("\033[s");
	printf("\033[J"); // clear below
	int selected = parse_args(argc, argv);
	int rc = 0;
	// Load configurations
	size_t config_count;
	Config* configs = load_configs(&config_count);
	if (!configs || config_count == 0) {
		fprintf(stderr, "❌ No configurations found\n");
		return 1;
	}

	if (selected != -1 && (selected < 1 || selected > config_count)) {
		fprintf(stderr, "❌  Incorrect selection\n");
		rc = 1;
		goto cleanup;
	}

	if (selected == -1) {
		// Show TUI
		selected = show_menu(configs, config_count);
		if (selected < 0) {
			printf("❌ Selection cancelled\n");
			rc = 1;
			goto cleanup;
		}
	} else {
		selected--;
	}

	Config sel_config = configs[selected];

	// Check if config changed
	State state = read_state();
	if (state.config && strcmp(sel_config.path, state.config) == 0) {
		if (kill(state.pid, 0) == 0) { // check process exists
			printf("🔁 Configuration unchanged\n");
			free(state.config);
			rc = 1;
			goto cleanup;
		}
	}
	free(state.config);

	if (access(sel_config.path, F_OK) != 0) {
		printf("❌Configuration file (%s) does not exist\n",
			   sel_config.path);
		rc = 1;
		goto cleanup;
	}

	// Start new process
	kill_previous_process();
	start_singbox(sel_config.path, sel_config.run_as_root);

cleanup:
	// Cleanup
	for (size_t i = 0; i < config_count; i++) {
		free(configs[i].name);
		free(configs[i].path);
	}
	free(configs);

	return rc;
}
