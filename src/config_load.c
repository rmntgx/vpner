#ifndef CONFIG_LOAD_C
#define CONFIG_LOAD_C

#include <cjson/cJSON.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include "utils.c"

typedef struct {
	char* name;
	char* path;
	bool run_as_root;
} Config;

char* get_config_path() {
	const char* app_name = "vpner";
	const char* config_home = getenv("XDG_CONFIG_HOME");
	char* config_path = malloc(PATH_MAX);

	if (config_home == NULL || config_home[0] == '\0') {
		const char* home_dir = getenv("HOME");
		if (home_dir == NULL) {
			home_dir = getpwuid(getuid())->pw_dir;
		}
		snprintf(config_path, PATH_MAX, "%s/.config/%s/configs.json", home_dir, app_name);
	} else {
		snprintf(config_path, PATH_MAX, "%s/%s/configs.json", config_home, app_name);
	}
	return config_path;
}

Config* load_configs(size_t* count) {
	char* config_path = get_config_path();
	char* cont = file_readall(config_path);
	if(!cont) return NULL;
	cJSON* root = cJSON_Parse(cont);
	free(cont);

	if (!root || !cJSON_IsObject(root)) {
		fprintf(stderr, "❌ Error parsing JSON\n");
		return NULL;
	}

	cJSON* configs = cJSON_GetObjectItem(root, "configs");
	if (!cJSON_IsArray(configs)) return NULL;
	*count = cJSON_GetArraySize(configs);
	Config* result = malloc(sizeof(Config) * (*count));

	for (size_t i = 0; i < *count; i++) {
		cJSON* item = cJSON_GetArrayItem(configs, i);
		if (!cJSON_IsObject(item)) return NULL;
		cJSON* name_item = cJSON_GetObjectItem(item, "name");
		cJSON* path_item = cJSON_GetObjectItem(item, "path");
		cJSON* rootflag_item = cJSON_GetObjectItem(item, "run_as_root");
		if (!cJSON_IsString(name_item)) return NULL;
		if (!cJSON_IsString(path_item)) return NULL;
		if(!cJSON_IsBool(rootflag_item))
			result[i].run_as_root = false;
		else
			result[i].run_as_root = cJSON_IsTrue(rootflag_item);
		result[i].name = strdup(name_item->valuestring);
		result[i].path = strdup(path_item->valuestring);

	}

	cJSON_Delete(root);
	return result;
}


char** get_configs_paths(int* count) {
    size_t cnt_conf;
    Config* cfgs = load_configs(&cnt_conf);

	uint64_t* hashes = malloc(cnt_conf * sizeof(uint64_t));
	size_t hash_cnt = 0;
	size_t new_cnt = 0;
	char** result = malloc(cnt_conf * sizeof(const char*));

    for (size_t i = 0; i < cnt_conf; i++) {
        char* path = cfgs[i].path;
		char* sl = strrchr(path, '/');
		if (sl) *sl = '\0';
		else *path = '\0';
		uint64_t hashv = 0;
		char* pathc = path;
		while (*pathc) hashv = (hashv << 5) - hashv + *pathc++; // hash
		bool uniq = true;
		for(size_t y = 0; y < hash_cnt; y++)
			if(hashv == hashes[y]) { uniq = false; break; }
		if(uniq) {
			hashes[hash_cnt++] = hashv;
			result[new_cnt++] = strdup(path);
		}
		free(cfgs[i].path);
		free(cfgs[i].name);
	}
	free(hashes);	
	free(cfgs);
    *count = new_cnt;
    return result;
}

bool modify_config(cJSON* outbound, const char* config_path) {
	char* cont = file_readall(config_path);
	if(!cont) return false;
	cJSON* root = cJSON_Parse(cont);
	free(cont);
	if (!root || !cJSON_IsObject(root)) {
		fprintf(stderr, "❌ Error parsing sing-box config\n"); // sing-box hardcode
		goto fail;
	}
	cJSON* outb = cJSON_GetObjectItem(root, "outbounds");
	if(!cJSON_IsArray(outb) || cJSON_GetArraySize(outb) <= 0) {
		fprintf(stderr, "❌ Error parsing sing-box config\n"); // sing-box hardcode
		goto fail;
	}
	size_t outb_size = cJSON_GetArraySize(outb);
	for(size_t i = 0; i < outb_size; i++) {
		cJSON* it = cJSON_GetArrayItem(outb, i);
		if(!cJSON_IsObject(it)) continue;
		cJSON* fi = cJSON_GetObjectItem(it, "tag");
		if(fi->valuestring && strcmp(fi->valuestring, "proxy") == 0) {
			cJSON_DeleteItemFromArray(outb, i);
			break;
		}
	}
	cJSON_InsertItemInArray(outb, 0, outbound);
	char* newcont = cJSON_Print(root);

	FILE* f = fopen(config_path, "w");
	if(!f) {
		fprintf(stderr, "❌ Error opening config file for writing\n"); // sing-box hardcode
		free(newcont);
		goto fail;
	}
	fwrite(newcont, strlen(newcont), 1, f);
	fclose(f);

	cJSON_Delete(root);
	return true;
fail:
	cJSON_Delete(root);
	return false;
}

bool new_conffile(const char* config_path, const char* content) {
	FILE* f = fopen(config_path, "w");
	if(!f) {
		fprintf(stderr, "❌ Error opening config file for writing\n");
	}
	fwrite(content, strlen(content), 1, f);
	fclose(f);

	char* vpner_path = get_config_path();
	char* cont = file_readall(vpner_path);
	if(!cont) return false;
	cJSON* root = cJSON_Parse(cont);
	free(cont);
	if (!root || !cJSON_IsObject(root)) return false;
	cJSON* configs = cJSON_GetObjectItem(root, "configs");
	if (!cJSON_IsArray(configs)) return false;

	cJSON* newcfg = cJSON_CreateObject();

	char* name = strdup(config_path);
	char* sl = strrchr(name, '/');
	if (sl) sl++;
	else sl = name;
	cJSON_AddItemToObject(newcfg, "name", cJSON_CreateString(sl));
	free(name);
	cJSON_AddItemToObject(newcfg, "path", cJSON_CreateString(config_path));
	cJSON_InsertItemInArray(configs, 0, newcfg);

	char* newcont = cJSON_Print(root);
	cJSON_Delete(root);

	f = fopen(vpner_path, "w");
	if(!f) {
		fprintf(stderr, "❌ Error opening vpner config file for writing\n");
		free(newcont);
	}
	fwrite(newcont, strlen(newcont), 1, f);
	fclose(f);

	return true;
}

#endif
