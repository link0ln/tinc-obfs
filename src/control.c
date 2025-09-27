/*
    control.c -- Control socket handling.
    Copyright (C) 2013 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"
#include "crypto.h"
#include "conf.h"
#include "control.h"
#include "control_common.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "names.h"
#include "net.h"
#include "obfs.h"
#include "netutl.h"
#include "protocol.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

char controlcookie[65];

typedef struct {
	bool has_enabled;
	bool enabled;
	bool has_junk_packet_count;
	int junk_packet_count;
	bool has_junk_packet_min_size;
	int junk_packet_min_size;
	bool has_junk_packet_max_size;
	int junk_packet_max_size;
	bool set_header_junk[OBFS_MESSAGE_KIND_COUNT];
	int header_junk[OBFS_MESSAGE_KIND_COUNT];
	bool set_magic_range[OBFS_MESSAGE_KIND_COUNT];
	obfs_magic_range_t magic_range[OBFS_MESSAGE_KIND_COUNT];
	bool disable_magic_range[OBFS_MESSAGE_KIND_COUNT];
	bool clear_tags;
	struct {
		char *name;
		char *pattern;
	} *new_tags;
	size_t new_tag_count;
	size_t new_tag_capacity;
} obfs_control_update_t;

static const char *obfs_kind_name(obfs_message_kind_t kind) {
	static const char *names[OBFS_MESSAGE_KIND_COUNT] = {
		"init",
		"response",
		"cookie",
		"transport",
	};

	if(kind >= OBFS_MESSAGE_KIND_COUNT) {
		return "unknown";
	}

	return names[kind];
}

static bool obfs_kind_from_string(const char *name, obfs_message_kind_t *kind_out) {
	if(!name || !kind_out) {
		return false;
	}

	for(obfs_message_kind_t k = 0; k < OBFS_MESSAGE_KIND_COUNT; ++k) {
		if(!strcasecmp(name, obfs_kind_name(k))) {
			*kind_out = k;
			return true;
		}
	}

	return false;
}

static bool parse_bool_token(const char *value, bool *out) {
	if(!value || !out) {
		return false;
	}

	if(!strcasecmp(value, "1") || !strcasecmp(value, "true") || !strcasecmp(value, "on") || !strcasecmp(value, "yes") || !strcasecmp(value, "enable") || !strcasecmp(value, "enabled")) {
		*out = true;
		return true;
	}

	if(!strcasecmp(value, "0") || !strcasecmp(value, "false") || !strcasecmp(value, "off") || !strcasecmp(value, "no") || !strcasecmp(value, "disable") || !strcasecmp(value, "disabled")) {
		*out = false;
		return true;
	}

	return false;
}

static bool parse_int_token(const char *value, int *out) {
	if(!value || !out) {
		return false;
	}

	char *endptr = NULL;
	errno = 0;
	long parsed = strtol(value, &endptr, 10);

	if(errno || !endptr || *endptr) {
		return false;
	}

	if(parsed < INT_MIN || parsed > INT_MAX) {
		return false;
	}

	*out = (int)parsed;
	return true;
}

static bool parse_uint32_range_token(const char *value, uint32_t *min_out, uint32_t *max_out) {
	if(!value || !min_out || !max_out) {
		return false;
	}

	char *copy = xstrdup(value);
	char *dash = strchr(copy, '-');
	char *first = copy;
	char *second = dash ? dash + 1 : NULL;

	if(dash) {
		*dash = '\0';
	}

	if(!*first) {
		free(copy);
		return false;
	}

	char *endptr = NULL;
	errno = 0;
	unsigned long min_val = strtoul(first, &endptr, 10);

	if(errno || !endptr || *endptr) {
		free(copy);
		return false;
	}

	unsigned long max_val = min_val;

	if(second && *second) {
		errno = 0;
		char *endptr2 = NULL;
		max_val = strtoul(second, &endptr2, 10);

		if(errno || !endptr2 || *endptr2) {
			free(copy);
			return false;
		}
	}

	free(copy);

	if(min_val > UINT32_MAX || max_val > UINT32_MAX) {
		return false;
	}

	if(min_val > max_val) {
		unsigned long tmp = min_val;
		min_val = max_val;
		max_val = tmp;
	}

	*min_out = (uint32_t)min_val;
	*max_out = (uint32_t)max_val;
	return true;
}

static bool obfs_should_enable_from_values(int junk_count, int junk_min, int junk_max, const int header_junk[OBFS_MESSAGE_KIND_COUNT], const obfs_magic_range_t magic_ranges[OBFS_MESSAGE_KIND_COUNT], size_t handshake_tag_count) {
	if(junk_count > 0 || junk_min > 0 || junk_max > 0) {
		return true;
	}

	for(obfs_message_kind_t k = 0; k < OBFS_MESSAGE_KIND_COUNT; ++k) {
		if(header_junk[k] > 0) {
			return true;
		}

		if(magic_ranges[k].enabled) {
			return true;
		}
	}

	return handshake_tag_count > 0;
}

static bool obfs_decode_base64_string(const char *value, char **out) {
	if(!value || !out) {
		return false;
	}

	size_t encoded_len = strlen(value);
	size_t buf_len = encoded_len / 4 * 3 + 4;
	char *decoded = xmalloc(buf_len + 1);
	size_t written = b64decode(value, decoded, encoded_len);

	if(encoded_len && !written) {
		free(decoded);
		return false;
	}

	decoded[written] = '\0';
	*out = decoded;
	return true;
}

static void obfs_control_update_cleanup(obfs_control_update_t *update) {
	if(!update) {
		return;
	}

	for(size_t i = 0; i < update->new_tag_count; ++i) {
		free(update->new_tags[i].name);
		free(update->new_tags[i].pattern);
	}

	free(update->new_tags);
	update->new_tags = NULL;
	update->new_tag_count = 0;
	update->new_tag_capacity = 0;
}

static bool obfs_control_append_tag(obfs_control_update_t *update, const char *name, char *pattern) {
	if(!update || !pattern) {
		free(pattern);
		return false;
	}

	if(update->new_tag_count == update->new_tag_capacity) {
		size_t new_capacity = update->new_tag_capacity ? update->new_tag_capacity * 2 : 4;
		update->new_tags = xrealloc(update->new_tags, new_capacity * sizeof(*update->new_tags));
		update->new_tag_capacity = new_capacity;
	}

	update->new_tags[update->new_tag_count].name = name ? xstrdup(name) : NULL;
	update->new_tags[update->new_tag_count].pattern = pattern;
	update->new_tag_count++;
	return true;
}

static bool obfs_tag_name_exists(const char *name) {
	if(!name) {
		return false;
	}

	for(size_t i = 0; i < obfs_config.handshake_tags.count; ++i) {
		if(obfs_config.handshake_tags.items[i].name && !strcasecmp(obfs_config.handshake_tags.items[i].name, name)) {
			return true;
		}
	}

	return false;
}

static bool control_return(connection_t *c, int type, int error) {
	return send_request(c, "%d %d %d", CONTROL, type, error);
}

static bool control_ok(connection_t *c, int type) {
	return control_return(c, type, 0);
}

bool control_h(connection_t *c, const char *request) {
	int type;

	if(!c->status.control || c->allow_request != CONTROL) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unauthorized control request from %s (%s)", c->name, c->hostname);
		return false;
	}

	if(sscanf(request, "%*d %d", &type) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "CONTROL", c->name, c->hostname);
		return false;
	}

	switch(type) {
	case REQ_STOP:
		event_exit();
		return control_ok(c, REQ_STOP);

	case REQ_DUMP_NODES:
		return dump_nodes(c);

	case REQ_DUMP_EDGES:
		return dump_edges(c);

	case REQ_DUMP_SUBNETS:
		return dump_subnets(c);

	case REQ_DUMP_CONNECTIONS:
		return dump_connections(c);

	case REQ_PURGE:
		purge();
		return control_ok(c, REQ_PURGE);

	case REQ_SET_DEBUG: {
		int new_level;

		if(sscanf(request, "%*d %*d %d", &new_level) != 1) {
			return false;
		}

		send_request(c, "%d %d %d", CONTROL, REQ_SET_DEBUG, debug_level);

		if(new_level >= 0) {
			debug_level = new_level;
		}

		return true;
	}

	case REQ_RETRY:
		retry();
		return control_ok(c, REQ_RETRY);

	case REQ_RELOAD:
		logger(DEBUG_ALWAYS, LOG_NOTICE, "Got '%s' command", "reload");
		int result = reload_configuration();
		return control_return(c, REQ_RELOAD, result);

	case REQ_DISCONNECT: {
		char name[MAX_STRING_SIZE];
		bool found = false;

		if(sscanf(request, "%*d %*d " MAX_STRING, name) != 1) {
			return control_return(c, REQ_DISCONNECT, -1);
		}

		for list_each(connection_t, other, connection_list) {
			if(strcmp(other->name, name)) {
				continue;
			}

			terminate_connection(other, other->edge);
			found = true;
		}

		return control_return(c, REQ_DISCONNECT, found ? 0 : -2);
	}

	case REQ_DUMP_TRAFFIC:
		return dump_traffic(c);

	case REQ_PCAP:
		sscanf(request, "%*d %*d %d", &c->outmaclength);
		c->status.pcap = true;
		pcap = true;
		return true;

	case REQ_LOG:
		sscanf(request, "%*d %*d %d", &c->outcompression);
		c->status.log = true;
		logcontrol = true;
		return true;

	case REQ_OBFS_STATUS: {
		const int junk_count = obfs_config.junk_packet_count;
		const int junk_min = obfs_config.junk_packet_min_size;
		const int junk_max = obfs_config.junk_packet_max_size;

		send_request(c, "%d %d enabled %d", CONTROL, REQ_OBFS_STATUS, obfs_config.enabled ? 1 : 0);
		send_request(c, "%d %d junk_count %d", CONTROL, REQ_OBFS_STATUS, junk_count);
		send_request(c, "%d %d junk_min %d", CONTROL, REQ_OBFS_STATUS, junk_min);
		send_request(c, "%d %d junk_max %d", CONTROL, REQ_OBFS_STATUS, junk_max);

		for(obfs_message_kind_t kind = 0; kind < OBFS_MESSAGE_KIND_COUNT; ++kind) {
			send_request(c, "%d %d header_junk %s %d", CONTROL, REQ_OBFS_STATUS,
			            obfs_kind_name(kind), obfs_config.header_junk[kind]);

			obfs_magic_range_t *range = &obfs_config.header_magic[kind];
			send_request(c, "%d %d magic %s %d %" PRIu32 " %" PRIu32, CONTROL, REQ_OBFS_STATUS,
			            obfs_kind_name(kind), range->enabled ? 1 : 0, range->min, range->max);
		}

		for(size_t idx = 0; idx < obfs_config.handshake_tags.count; ++idx) {
			obfs_tag_def_t *tag = &obfs_config.handshake_tags.items[idx];
			const char *name = tag->name ? tag->name : "-";
			const char *pattern = tag->pattern ? tag->pattern : "";
			size_t pattern_len = strlen(pattern);
			size_t encoded_len = pattern_len / 3 * 4 + 4;
			char *encoded = xmalloc(encoded_len + 1);
			size_t produced = b64encode(pattern, encoded, pattern_len);
			encoded[produced] = '\0';
			send_request(c, "%d %d tag %s %s", CONTROL, REQ_OBFS_STATUS, name, encoded);
			free(encoded);
		}

		send_request(c, "%d %d handshake_tags %zu", CONTROL, REQ_OBFS_STATUS,
		            obfs_config.handshake_tags.count);

		return send_request(c, "%d %d", CONTROL, REQ_OBFS_STATUS);
	}

	case REQ_OBFS_APPLY: {
		const char *payload = request;
		payload = strchr(payload, ' ');
		if(!payload) {
			return control_return(c, REQ_OBFS_APPLY, -EINVAL);
		}

		payload = strchr(payload + 1, ' ');
		if(!payload) {
			return control_return(c, REQ_OBFS_APPLY, -EINVAL);
		}

		while(*payload && isspace((unsigned char)*payload)) {
			++payload;
		}

		if(!*payload) {
			return control_return(c, REQ_OBFS_APPLY, -EINVAL);
		}

		obfs_control_update_t update = {0};
		bool have_tokens = false;
		bool parse_error = false;
		char *copy = xstrdup(payload);
		char *saveptr = NULL;

		for(char *token = strtok_r(copy, " 	\r\n", &saveptr); token; token = strtok_r(NULL, " 	\r\n", &saveptr)) {
			have_tokens = true;
			char *eq = strchr(token, '=');

			if(!eq) {
				parse_error = true;
				break;
			}

			*eq = '\0';
			const char *key = token;
			const char *value = eq + 1;

			if(!strcmp(key, "enabled")) {
				bool enabled;

				if(!parse_bool_token(value, &enabled)) {
					parse_error = true;
					break;
				}

				update.has_enabled = true;
				update.enabled = enabled;
				continue;
			}

			if(!strcmp(key, "junk_count")) {
				int v;

				if(!parse_int_token(value, &v)) {
					parse_error = true;
					break;
				}

				update.has_junk_packet_count = true;
				update.junk_packet_count = v;
				continue;
			}

			if(!strcmp(key, "junk_min")) {
				int v;

				if(!parse_int_token(value, &v)) {
					parse_error = true;
					break;
				}

				update.has_junk_packet_min_size = true;
				update.junk_packet_min_size = v;
				continue;
			}

			if(!strcmp(key, "junk_max")) {
				int v;

				if(!parse_int_token(value, &v)) {
					parse_error = true;
					break;
				}

				update.has_junk_packet_max_size = true;
				update.junk_packet_max_size = v;
				continue;
			}

			if(!strcmp(key, "tags_clear")) {
				bool flag;

				if(!parse_bool_token(value, &flag)) {
					parse_error = true;
					break;
				}

				update.clear_tags = flag;
				continue;
			}

			if(!strcmp(key, "add_tag_b64")) {
				char *decoded = NULL;

				if(!obfs_decode_base64_string(value, &decoded)) {
					parse_error = true;
					break;
				}

				obfs_control_append_tag(&update, NULL, decoded);
				continue;
			}

			if(!strcmp(key, "add_tag_named_b64")) {
				char *colon = strchr(value, ':');

				if(!colon || colon == value || !colon[1]) {
					parse_error = true;
					break;
				}

				size_t name_len = (size_t)(colon - value);
				char *basename = xmalloc(name_len + 1);
				memcpy(basename, value, name_len);
				basename[name_len] = '\0';

				if(!check_id(basename)) {
					free(basename);
					parse_error = true;
					break;
				}

				char *decoded = NULL;

				if(!obfs_decode_base64_string(colon + 1, &decoded)) {
					free(basename);
					parse_error = true;
					break;
				}

				obfs_control_append_tag(&update, basename, decoded);
				free(basename);
				continue;
			}

			if(!strncmp(key, "header_junk_", 12)) {
				const char *suffix = key + 12;
				obfs_message_kind_t kind;

				if(!obfs_kind_from_string(suffix, &kind)) {
					parse_error = true;
					break;
				}

				int v;

				if(!parse_int_token(value, &v) || v < 0) {
					parse_error = true;
					break;
				}

				update.set_header_junk[kind] = true;
				update.header_junk[kind] = v;
				continue;
			}

			if(!strncmp(key, "magic_", 6)) {
				const char *suffix = key + 6;
				obfs_message_kind_t kind;

				if(!obfs_kind_from_string(suffix, &kind)) {
					parse_error = true;
					break;
				}

				if(!strcasecmp(value, "off") || !strcasecmp(value, "none") || !strcasecmp(value, "disable")) {
					update.disable_magic_range[kind] = true;
					update.set_magic_range[kind] = false;
					continue;
				}

				uint32_t min_val;
				uint32_t max_val;

				if(!parse_uint32_range_token(value, &min_val, &max_val)) {
					parse_error = true;
					break;
				}

				update.set_magic_range[kind] = true;
				update.disable_magic_range[kind] = false;
				update.magic_range[kind].min = min_val;
				update.magic_range[kind].max = max_val;
				update.magic_range[kind].enabled = true;
				continue;
			}

			parse_error = true;
			break;
		}

		free(copy);

		if(parse_error || !have_tokens) {
			obfs_control_update_cleanup(&update);
			return control_return(c, REQ_OBFS_APPLY, -EINVAL);
		}

		int header_junk[OBFS_MESSAGE_KIND_COUNT];
		obfs_magic_range_t magic_ranges[OBFS_MESSAGE_KIND_COUNT];

		for(obfs_message_kind_t kind = 0; kind < OBFS_MESSAGE_KIND_COUNT; ++kind) {
			header_junk[kind] = obfs_config.header_junk[kind];
			magic_ranges[kind] = obfs_config.header_magic[kind];

			if(update.set_header_junk[kind]) {
				header_junk[kind] = update.header_junk[kind];
			}

			if(update.disable_magic_range[kind]) {
				magic_ranges[kind].enabled = false;
			}

			if(update.set_magic_range[kind]) {
				magic_ranges[kind] = update.magic_range[kind];
			}
		}

		int junk_count = update.has_junk_packet_count ? update.junk_packet_count : obfs_config.junk_packet_count;
		int junk_min = update.has_junk_packet_min_size ? update.junk_packet_min_size : obfs_config.junk_packet_min_size;
		int junk_max = update.has_junk_packet_max_size ? update.junk_packet_max_size : obfs_config.junk_packet_max_size;

		if(junk_count < 0 || junk_min < 0 || junk_max < 0) {
			obfs_control_update_cleanup(&update);
			return control_return(c, REQ_OBFS_APPLY, -EINVAL);
		}

		for(obfs_message_kind_t kind = 0; kind < OBFS_MESSAGE_KIND_COUNT; ++kind) {
			if(header_junk[kind] < 0 || header_junk[kind] >= MTU) {
				obfs_control_update_cleanup(&update);
				return control_return(c, REQ_OBFS_APPLY, -EINVAL);
			}
		}

		if(junk_count > 0) {
			if(junk_min <= 0 || junk_max <= 0 || junk_min > junk_max || junk_max >= MTU) {
				obfs_control_update_cleanup(&update);
				return control_return(c, REQ_OBFS_APPLY, -EINVAL);
			}
		}

		for(obfs_message_kind_t kind = 0; kind < OBFS_MESSAGE_KIND_COUNT; ++kind) {
			if(magic_ranges[kind].enabled && magic_ranges[kind].min > magic_ranges[kind].max) {
				obfs_control_update_cleanup(&update);
				return control_return(c, REQ_OBFS_APPLY, -EINVAL);
			}
		}

		for(size_t i = 0; i < update.new_tag_count; ++i) {
			char *err = NULL;

			if(update.new_tags[i].name && (!check_id(update.new_tags[i].name) || (obfs_tag_name_exists(update.new_tags[i].name) && !update.clear_tags))) {
				obfs_control_update_cleanup(&update);
				return control_return(c, REQ_OBFS_APPLY, -EINVAL);
			}

			for(size_t j = i + 1; j < update.new_tag_count; ++j) {
				if(update.new_tags[i].name && update.new_tags[j].name && !strcasecmp(update.new_tags[i].name, update.new_tags[j].name)) {
					obfs_control_update_cleanup(&update);
					return control_return(c, REQ_OBFS_APPLY, -EINVAL);
				}
			}

			if(!obfs_validate_handshake_pattern(update.new_tags[i].pattern, &err)) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Obfs: invalid handshake tag pattern: %s", err ? err : "unknown");
				free(err);
				obfs_control_update_cleanup(&update);
				return control_return(c, REQ_OBFS_APPLY, -EINVAL);
			}

			free(err);
		}

		obfs_config.junk_packet_count = junk_count;
		obfs_config.junk_packet_min_size = junk_min;
		obfs_config.junk_packet_max_size = junk_max;

		for(obfs_message_kind_t kind = 0; kind < OBFS_MESSAGE_KIND_COUNT; ++kind) {
			obfs_config.header_junk[kind] = header_junk[kind];
			obfs_config.header_magic[kind] = magic_ranges[kind];
		}

		if(update.clear_tags) {
			if(obfs_config.handshake_tags.count) {
				logger(DEBUG_STATUS, LOG_INFO, "Obfs: cleared handshake tags");
			}
			obfs_clear_tags();
		}

		size_t final_tag_count = obfs_config.handshake_tags.count;

		for(size_t i = 0; i < update.new_tag_count; ++i) {
			const char *name = update.new_tags[i].name;
			char namebuf[32];

			if(!name) {
				size_t suffix = final_tag_count + 1;
				while(true) {
					snprintf(namebuf, sizeof(namebuf), "runtime%zu", suffix++);
					if(!obfs_tag_name_exists(namebuf)) {
						break;
					}
				}

				name = namebuf;
			}

			char *err = NULL;

			if(!obfs_append_tag_definition(name, update.new_tags[i].pattern, &err)) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Obfs: failed to append handshake tag %s: %s", name, err ? err : "unknown");
				free(err);
				obfs_control_update_cleanup(&update);
				return control_return(c, REQ_OBFS_APPLY, -EINVAL);
			}

			free(err);
			final_tag_count = obfs_config.handshake_tags.count;
		}

		bool auto_enabled = obfs_should_enable_from_values(junk_count, junk_min, junk_max, header_junk, magic_ranges, final_tag_count);
		bool previous = obfs_config.enabled;
		obfs_config.enabled = update.has_enabled ? update.enabled : auto_enabled;

		if(obfs_config.enabled != previous) {
			logger(DEBUG_STATUS, LOG_INFO, "Obfs: control updated (enabled=%s)", obfs_config.enabled ? "yes" : "no");
		}

		obfs_control_update_cleanup(&update);
		return control_return(c, REQ_OBFS_APPLY, 0);
	}

	default:
		return send_request(c, "%d %d", CONTROL, REQ_INVALID);
	}
}

bool init_control(void) {
	randomize(controlcookie, sizeof(controlcookie) / 2);
	bin2hex(controlcookie, controlcookie, sizeof(controlcookie) / 2);

	mode_t mask = umask(0);
	umask(mask | 077);
	FILE *f = fopen(pidfilename, "w");
	umask(mask);

	if(!f) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot write control socket cookie file %s: %s", pidfilename, strerror(errno));
		return false;
	}

	// Get the address and port of the first listening socket

	char *localhost = NULL;
	sockaddr_t sa = {0};
	socklen_t len = sizeof(sa);

	// Make sure we have a valid address, and map 0.0.0.0 and :: to 127.0.0.1 and ::1.

	if(getsockname(listen_socket[0].tcp.fd, &sa.sa, &len)) {
		xasprintf(&localhost, "127.0.0.1 port %s", myport);
	} else {
		if(sa.sa.sa_family == AF_INET) {
			if(sa.in.sin_addr.s_addr == 0) {
				sa.in.sin_addr.s_addr = htonl(0x7f000001);
			}
		} else if(sa.sa.sa_family == AF_INET6) {
			static const uint8_t zero[16] = {0};

			if(!memcmp(sa.in6.sin6_addr.s6_addr, zero, sizeof(zero))) {
				sa.in6.sin6_addr.s6_addr[15] = 1;
			}
		}

		localhost = sockaddr2hostname(&sa);
	}

	fprintf(f, "%d %s %s\n", (int)getpid(), controlcookie, localhost);

	free(localhost);
	fclose(f);

#ifndef HAVE_MINGW
	int unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if(unix_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create UNIX socket: %s", sockstrerror(sockerrno));
		return false;
	}

	struct sockaddr_un sa_un;

	sa_un.sun_family = AF_UNIX;

	strncpy(sa_un.sun_path, unixsocketname, sizeof(sa_un.sun_path));

	sa_un.sun_path[sizeof(sa_un.sun_path) - 1] = 0;

	if(connect(unix_fd, (struct sockaddr *)&sa_un, sizeof(sa_un)) >= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "UNIX socket %s is still in use!", unixsocketname);
		return false;
	}

	unlink(unixsocketname);

	umask(mask | 077);
	int result = bind(unix_fd, (struct sockaddr *)&sa_un, sizeof(sa_un));
	umask(mask);

	if(result < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not bind UNIX socket to %s: %s", unixsocketname, sockstrerror(sockerrno));
		return false;
	}

	if(listen(unix_fd, 3) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not listen on UNIX socket %s: %s", unixsocketname, sockstrerror(sockerrno));
		return false;
	}

	io_add(&unix_socket, handle_new_unix_connection, &unix_socket, unix_fd, IO_READ);
#endif

	return true;
}

void exit_control(void) {
#ifndef HAVE_MINGW
	unlink(unixsocketname);
	io_del(&unix_socket);
	close(unix_socket.fd);
#endif

	unlink(pidfilename);
}
