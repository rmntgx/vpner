#include <stdio.h>
#include "utils.c"
#include "config_load.c"

void tui_print_main_menu(Config* configs, int count, int selected) {
	printf("\033[33m[?] Select configuration:\033[0m\n");
	for (int i = 0; i < count; i++) {
		if (i == selected) {
			printf("\033[94m> %s\033[0m\n", configs[i].name);
		} else {
			printf("  %s\n", configs[i].name);
		}
	}
}

int handle_main_input(int count, int* selected) {
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

int launch_main_tui(Config* configs, int count) {
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
	tui_print_main_menu(configs, count, selected);

	// Move cursor to menu start position and save
	printf("\033[%dA", menu_lines);
	printf("\033[s");

	while (1) {
		int r = handle_main_input(count, &selected);
		if (r == 1) {
			// Redraw menu at saved position
			printf("\033[u");
			tui_print_main_menu(configs, count, selected);
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

