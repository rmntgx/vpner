#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <pwd.h>
#include <fcntl.h>
#include "cjson/cJSON.h"
#include "help.h"

#define STATE_FILE "/tmp/.vpner_state.json"

typedef struct {
	char *name;
	char *path;
} Config;

typedef struct {
	int pid;
	char *config;
} State;

// Terminal handling
struct termios orig_termios;

void disable_raw_mode() {
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode() {
	tcgetattr(STDIN_FILENO, &orig_termios);
	atexit(disable_raw_mode);
	struct termios raw = orig_termios;
	raw.c_lflag &= ~(ECHO | ICANON | ISIG); // Disable signal processing
	raw.c_cc[VMIN] = 0;
	raw.c_cc[VTIME] = 1;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

char* get_config_path() {
	const char* app_name = "vpner";
	const char *config_home = getenv("XDG_CONFIG_HOME");
	char* config_path = malloc(PATH_MAX);

	if (config_home == NULL || config_home[0] == '\0') {
        const char *home_dir = getenv("HOME");
        if (home_dir == NULL) {
            home_dir = getpwuid(getuid())->pw_dir;
        }
        snprintf(config_path, PATH_MAX, "%s/.config/%s/configs.json", home_dir, app_name);
    } else {
        snprintf(config_path, PATH_MAX, "%s/%s/configs.json", config_home, app_name);
    }
	return config_path;
}

// TUI functions
void print_menu(Config *configs, int count, int selected) {
	printf("\033[33m[?] Select configuration:\033[0m\n");
	for (int i = 0; i < count; i++) {
		if (i == selected) {
			printf("\033[94m> %s\033[0m\n", configs[i].name);
		} else {
			printf("  %s\n", configs[i].name);
		}
	}
}

int handle_input(int count, int *selected) {
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
		} else if(c == 'j' || c == 'J') {
			if (*selected < count - 1) (*selected)++;
			else (*selected) = 0;
			return 1;
		}
	}
	return 0;
}

int show_menu(Config *configs, int count) {
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
			
			// Move cursor back to menu start and save again
			printf("\033[%dA", menu_lines);
			printf("\033[s");
			fflush(stdout);
		} else if (r == 2 || r == -1) {
			result = (r == 2) ? selected : -1;
			break;
		}
	}

	// Clear menu area on exit
	printf("\033[u");
	for (int i = 0; i < menu_lines; i++) {
		printf("\033[K\n"); // Clear each line
	}
	printf("\033[%dA", menu_lines); // Move back up

	printf("\033[?25h"); // Show cursor
	disable_raw_mode();
	return result;
}

// Config loading
Config* load_configs(int *count) {
	char* config_path = get_config_path();
	FILE *f = fopen(config_path, "r");

	if (!f) {
		fprintf(stderr, "❌ Error opening %s file\n", config_path);
		return NULL;
	}
	free(config_path);

	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *data = malloc(len + 1);
	if(!data) {
		fclose(f);
		return NULL;
	}
	size_t ret = fread(data, 1, len, f);
	fclose(f);
	if(ret != (size_t)len) {
		fprintf(stderr, "❌ Reading error opening configs.json file\n");
		free(data);
		return NULL;
	}
	data[len] = 0;

	cJSON *root = cJSON_Parse(data);
	free(data);
	if (!root) {
		fprintf(stderr, "❌ Error parsing JSON\n");
		return NULL;
	}
	if(!cJSON_IsObject(root)) return NULL;

	cJSON *configs = cJSON_GetObjectItem(root, "configs");
	if(!cJSON_IsArray(configs)) return NULL;
	*count = cJSON_GetArraySize(configs);
	Config *result = malloc(sizeof(Config) * (*count));

	for (int i = 0; i < *count; i++) {
		cJSON *item = cJSON_GetArrayItem(configs, i);
		if(!cJSON_IsObject(item)) return NULL;
		cJSON* nameitem = cJSON_GetObjectItem(item, "name");
		cJSON* pathitem = cJSON_GetObjectItem(item, "path");
		if(!cJSON_IsString(nameitem)) return NULL;
		if(!cJSON_IsString(pathitem)) return NULL;
		result[i].name = strdup(nameitem->valuestring);
		result[i].path = strdup(pathitem->valuestring);
	}

	cJSON_Delete(root);
	return result;
}

// State handling
State read_state() {
	State state = {0};
	FILE *f = fopen(STATE_FILE, "r");
	if (!f) return state;

	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *data = malloc(len + 1);
	if(!data) {
		fclose(f);
		return state;
	}
	size_t ret = fread(data, 1, len, f);
	fclose(f);
	if(ret != (size_t)len) {
		fprintf(stderr, "❌ Reading error opening state file\n");
		free(data);
		return state;
	}
	data[len] = 0;

	cJSON *root = cJSON_Parse(data);
	free(data);
	if (!root) return state;
	if(!cJSON_IsObject(root)) return state;
	
	cJSON* piditem = cJSON_GetObjectItem(root, "pid");
	if(!cJSON_IsNumber(piditem)) return state;
	cJSON *config = cJSON_GetObjectItem(root, "config");
	if(!cJSON_IsString(config)) return state;
	state.config = config ? strdup(config->valuestring) : NULL;
	state.pid = piditem->valueint;

	cJSON_Delete(root);
	return state;
}

void write_state(pid_t pid, const char *config) {
	cJSON *root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "pid", pid);
	cJSON_AddStringToObject(root, "config", config);

	char *data = cJSON_Print(root);
	FILE *f = fopen(STATE_FILE, "w");
	if (f) {
		fputs(data, f);
		fclose(f);
	}    
	free(data);
	cJSON_Delete(root);
}

void kill_previous_process() {
	State state = read_state();
	if (state.pid == 0) return;

	// Check if process exists
	if (kill(state.pid, 0) == 0) {
		printf("🔁 Stopping previous process (PID: %d)\n", state.pid);
		kill(state.pid, SIGTERM);
	} else {
		printf("⚠️ Previous process not running\n");
	}

	remove(STATE_FILE);
	free(state.config);
}

// Process management
void start_singbox(const char *config_path) {
	pid_t pid = fork();
	if (pid == 0) { // Child
		setsid();
		FILE* ret = freopen("/dev/null", "r", stdin);
		if(ret == NULL) exit(EXIT_FAILURE);
		ret = freopen("/dev/null", "w", stdout);
		if(ret == NULL) exit(EXIT_FAILURE);
		ret = freopen("/dev/null", "w", stderr);
		if(ret == NULL) exit(EXIT_FAILURE);

		char *args[] = {"sing-box", "run", "-c", (char*)config_path, NULL};
		execvp("sing-box", args);
		exit(EXIT_FAILURE);
	} else if (pid > 0) { // Parent
		write_state(pid, config_path);
		printf("✅ sing-box started with PID: %d\n", pid);
	} else {
		perror("❌ Fork failed");
	}
}

// Add before main logic
int parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
		if(argv[i][0] != '-') break;

		size_t stlen = strlen(argv[i]);
		bool fullnum = true;
		for(size_t y = 1; y < stlen; y++) {
			if(!(argv[i][y] >= '0' && argv[i][y] <= '9')) {
				fullnum = false;
				break;
			}
		}
		if(fullnum) {
			return atoi(argv[i] + 1);
		}
		else if (strcmp(argv[i], "--help") == 0) {
            printf(HELP_TEXT); // Use the help text above
            exit(0);
        }
        else if (strcmp(argv[i], "--stop") == 0) {
            kill_previous_process();
            exit(0);
        }
        else if (strcmp(argv[i], "--status") == 0) {
            State state = read_state();
            if (state.pid && kill(state.pid, 0) == 0) {
                printf("VPN running (PID: %d, Config: %s)\n", state.pid, state.config);
            } else {
                printf("No VPN running\n");
            }
            exit(0);
        }
        else if (strcmp(argv[i], "--list") == 0) {
            int count;
            Config *configs = load_configs(&count);
            for (int i = 0; i < count; i++) {
                printf("%s (%s)\n", configs[i].name, configs[i].path);
            }
            exit(0);
        }
        else if (strcmp(argv[i], "--list-rofi") == 0) {
            int count;
            Config *configs = load_configs(&count);
            State state = read_state();
            if (state.pid && kill(state.pid, 0) == 0) {
				for (int i = 0; i < count; i++) {
					if(strcmp(configs[i].path, state.config) == 0)
						printf("✔️ %s\n", configs[i].name);
					else
						printf("%i) %s\n", i + 1, configs[i].name);
				}
            } else {
				for (int i = 0; i < count; i++) {
					printf("%i) %s\n", i + 1, configs[i].name);
				}
            }
            exit(0);
        }
    }
    return -1;
}

int main(int argc, char *argv[]) {
	int selected = parse_args(argc, argv);
	int rc = 0;

	// Load configurations
	int config_count;
	Config *configs = load_configs(&config_count);
	if (!configs || config_count == 0) {
		fprintf(stderr, "❌ No configurations found\n");
		return 1;
	}

	if(selected != -1 && (selected < 1 || selected > config_count)) {
		fprintf(stderr, "❌  Incorrect selection\n");
		rc = 1;
		goto cleanup;
	}

	if(selected == -1) {
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

	// Check if config changed
	State state = read_state();
	if (state.config && strcmp(configs[selected].path, state.config) == 0) {
		if(kill(state.pid, 0) == 0) { // check process exists
			printf("🔁 Configuration unchanged\n");
			free(state.config);
			rc = 1;
			goto cleanup;
		}
	}
	free(state.config);

	if (access(configs[selected].path, F_OK) != 0) {
		printf("❌Configuration file (%s) does not exist\n", configs[selected].path);
		rc = 1;
		goto cleanup;
	}

	// Start new process
	kill_previous_process();
	start_singbox(configs[selected].path);
	
cleanup:
	// Cleanup
	for (int i = 0; i < config_count; i++) {
		free(configs[i].name);
		free(configs[i].path);
	}
	free(configs);

	return rc;
}
