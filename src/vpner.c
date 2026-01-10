#include <assert.h>
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
#include "urlconfig/urlconfig.h"
#include "tui_main.c"

#define STATE_FILE "/tmp/.vpner_state.json"
#define LOG_FILE "/tmp/.vpner_log.txt"

typedef struct {
	int pid;
	char* config;
} State;

// State handling
State read_state() {
	State state = {0};
	char* data = file_readall(STATE_FILE, true);
	if(!data) return state;
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

void show_logs() {
	if (access(LOG_FILE, F_OK) == 0) {
		pid_t pid = fork();
		if (pid == 0) {
			char* args[] = {"less", LOG_FILE, NULL};
			execvp("less", args);
			char* args2[] = {"more", LOG_FILE, NULL};
			execvp("more", args2);
			char* log_content = file_readall(LOG_FILE, false);
			if (log_content != NULL) {
				printf("Sing-box logs:\n");
				printf("%s", log_content);
				free(log_content);
			}
			exit(0);
		} else if (pid > 0) {
			int status;
			waitpid(pid, &status, 0);
		} else {
			perror("❌ Fork failed");
		}
	} else {
		printf("❌ There are no logs\n");
	}
}

void show_logs_prompt(const char* message) {
	printf("%s", message);
	printf("Show logs? [Y/n]: ");
	char response;
	scanf(" %c", &response);
	if (response == 'Y' || response == 'y' || response == '\n') {
		show_logs();
	}
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
			assert(len != -1);
			self_path[len] = '\0';
			pid_t pid = fork();
			if (pid == 0) {
				char* args[] = {"sudo", "-k", self_path, "--stop", NULL};
				execvp("sudo", args);
			} else {
				printf("🔐 Waiting for password...\n");
				waitpid(pid, NULL, 0);
			}
		}
	} else {
		// Process in state file doesn't exist, prompt for logs
		if (access(LOG_FILE, F_OK) == 0) {
			char message[256];
			snprintf(message, sizeof(message), "⚠️ Previous process (PID: %d) not running\n", state.pid);
			show_logs_prompt(message);
		} else {
			printf("⚠️ Previous process (PID: %d) not running\n", state.pid);
		}
	}

	remove(STATE_FILE);
	free(state.config);
}

void run_singbox_in_fork(const char* config_path) {
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        freopen("/dev/null", "r", stdin);

        // Create log file path
        char log_path[PATH_MAX];
        snprintf(log_path, sizeof(log_path), LOG_FILE);

        // Redirect both stdout and stderr to the same log file
        FILE* log_file = fopen(log_path, "w");
        if (log_file) {
            fclose(log_file);
            freopen(log_path, "w", stdout);
            freopen(log_path, "w", stderr);
        }

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
            char* args[] = {"sudo", "-k", self_path, "--run-root-internal", (char*)config_path, NULL};
            execvp("sudo", args);
            perror("❌ Failed to exec sudo");
            exit(EXIT_FAILURE);
        } else if (pid > 0) {
            printf("🔐 Waiting for password...\n");
            waitpid(pid, NULL, 0);
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
		} else if (strcmp(argv[i], "--log") == 0 || strcmp(argv[i], "-l") == 0) {
            show_logs();
            exit(0);
		} else if (strcmp(argv[i], "--status") == 0) {
			State state = read_state();
			if (state.pid && getpgid(state.pid) >= 0) {
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
			if (state.pid && getpgid(state.pid) >= 0) {
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
			tcgetattr(STDIN_FILENO, &orig_termios);
			printf("\033[s");
			printf("\033[J"); // clear below
			launch_urlconfig_tui();
			exit(0);
		}
	}
	return -1;
}

int main(int argc, char* argv[]) {
	int selected = parse_args(argc, argv);
	int rc = 0;
	// Load configurations
	size_t config_count;
	Config* configs = load_configs(&config_count);
	if (!configs || config_count == 0) {
		fprintf(stderr, "❌ No configurations found\n");
		return 1;
	}

	if (selected != -1 && (selected < 1 || selected > (int)config_count)) {
		fprintf(stderr, "❌ Incorrect selection\n");
		rc = 1;
		goto cleanup;
	}

	if (selected == -1) {
		// Show TUI
		tcgetattr(STDIN_FILENO, &orig_termios);	
		printf("\033[s");
		printf("\033[J"); // clear below
		selected = launch_main_tui(configs, config_count);
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
		if (getpgid(state.pid) >= 0) { // check process exists
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
