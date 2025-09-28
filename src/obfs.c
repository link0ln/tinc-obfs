#include "obfs.h"

#include "crypto.h"
#include "logger.h"
#include "net.h"
#include "sptps.h"
#include "xalloc.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <time.h>
#include <stdlib.h>
#include <string.h>

static const char obfs_alnum_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static uint64_t obfs_packet_counter;

static uint32_t obfs_random_u32(void) {
	uint32_t value;
	randomize(&value, sizeof(value));
	return value;
}

uint64_t obfs_counter_next_value(void) {
	return obfs_packet_counter + 1;
}

void obfs_record_sent_packet(void) {
	obfs_record_sent_packets(1);
}

void obfs_record_sent_packets(size_t count) {
	if(!count) {
		return;
	}

	obfs_packet_counter += count;
}

static obfs_blob_t obfs_new_blob(size_t size);

static uint64_t obfs_hton64(uint64_t value) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t high = htonl((uint32_t)(value >> 32));
	uint32_t low = htonl((uint32_t)(value & 0xffffffffu));
	return ((uint64_t)low << 32) | high;
#else
	return value;
#endif
}

static char *obfs_trim(char *text) {
	if(!text) {
		return NULL;
	}

	while(*text && isspace((unsigned char)*text)) {
		++text;
	}

	char *end = text + strlen(text);

	while(end > text && isspace((unsigned char)end[-1])) {
		--end;
	}

	*end = '\0';
	return text;
}

static bool obfs_parse_uint(const char *input, unsigned int *value_out) {
	if(!input || !value_out) {
		return false;
	}

	char *copy = xstrdup(input);
	char *trimmed = obfs_trim(copy);

	if(!*trimmed) {
		free(copy);
		return false;
	}

	errno = 0;
	char *endptr = NULL;
	unsigned long value = strtoul(trimmed, &endptr, 10);

	if(errno || endptr == trimmed) {
		free(copy);
		return false;
	}

	trimmed = obfs_trim(endptr);
	bool ok = !*trimmed && value <= UINT32_MAX;

	if(ok) {
		*value_out = (unsigned int)value;
	}

	free(copy);
	return ok;
}

static bool obfs_parse_hex_bytes(const char *input, obfs_blob_t *out) {
	if(!input || !out) {
		return false;
	}

	char *copy = xstrdup(input);
	char *trimmed = obfs_trim(copy);

	if(!*trimmed) {
		free(copy);
		return false;
	}

	if(strncasecmp(trimmed, "0x", 2) == 0) {
		trimmed += 2;
	}

	if(*trimmed == '\0') {
		free(copy);
		return false;
	}

	size_t len = strlen(trimmed);

	if(len % 2 != 0) {
		char *tmp = xmalloc(len + 2);
		tmp[0] = '0';
		memcpy(tmp + 1, trimmed, len + 1);
		free(copy);
		copy = tmp;
		trimmed = copy;
		len += 1;
	}

	obfs_blob_t blob = obfs_new_blob(len / 2);

	if(!blob.data) {
		free(copy);
		return false;
	}

	for(size_t i = 0; i < len; i += 2) {
		char byte_str[3] = { trimmed[i], trimmed[i + 1], '\0' };
		char *endptr = NULL;
		errno = 0;
		unsigned long value = strtoul(byte_str, &endptr, 16);

		if(errno || endptr != byte_str + 2) {
			obfs_free_blob(&blob);
			free(copy);
			return false;
		}

		blob.data[i / 2] = (uint8_t)value;
	}

	*out = blob;
	free(copy);
	return true;
}

static void obfs_free_tag(obfs_tag_def_t *tag) {
	if(!tag) {
		return;
	}

	for(size_t i = 0; i < tag->generator_count; ++i) {
		obfs_free_blob(&tag->generators[i].literal);
	}

	free(tag->generators);
	free(tag->name);
	free(tag->pattern);
	memset(tag, 0, sizeof(*tag));
}

obfs_config_t obfs_config;

void obfs_disable_all_ranges(void) {
	for(size_t i = 0; i < OBFS_MESSAGE_KIND_COUNT; ++i) {
		obfs_config.header_magic[i].enabled = false;
		obfs_config.header_magic[i].min = 0;
		obfs_config.header_magic[i].max = 0;
	}
}

static void obfs_reset_header_junk(void) {
	for(size_t i = 0; i < OBFS_MESSAGE_KIND_COUNT; ++i) {
		obfs_config.header_junk[i] = 0;
	}
}

void obfs_clear_tags(void) {
	for(size_t i = 0; i < obfs_config.handshake_tags.count; ++i) {
		obfs_free_tag(&obfs_config.handshake_tags.items[i]);
	}

	free(obfs_config.handshake_tags.items);
	obfs_config.handshake_tags.items = NULL;
	obfs_config.handshake_tags.count = 0;
	obfs_config.handshake_tags.capacity = 0;
}

void obfs_reset(void) {
	obfs_config.enabled = false;
	obfs_config.junk_packet_count = 0;
	obfs_config.junk_packet_min_size = 0;
	obfs_config.junk_packet_max_size = 0;

	obfs_reset_header_junk();
	obfs_disable_all_ranges();
	obfs_clear_tags();
	obfs_packet_counter = 0;
}

void obfs_init(void) {
	obfs_reset();
}

static obfs_blob_t obfs_new_blob(size_t size) {
	obfs_blob_t blob = {0};

	if(!size) {
		return blob;
	}

	blob.data = xmalloc(size);
	blob.len = size;
	return blob;
}

static bool obfs_append_generator(obfs_tag_def_t *def, obfs_tag_generator_kind_t kind, int param, const obfs_blob_t *literal) {
	if(!def) {
		return false;
	}

	if(def->generator_count == def->generator_capacity) {
		size_t new_capacity = def->generator_capacity ? def->generator_capacity * 2 : 4;
		def->generators = xrealloc(def->generators, new_capacity * sizeof(*def->generators));

		for(size_t i = def->generator_capacity; i < new_capacity; ++i) {
			memset(&def->generators[i], 0, sizeof(def->generators[i]));
		}

		def->generator_capacity = new_capacity;
	}

	obfs_tag_generator_t *gen = &def->generators[def->generator_count++];
	memset(gen, 0, sizeof(*gen));
	gen->kind = kind;
	gen->param = param;

	if(literal && literal->data && literal->len) {
		gen->literal = obfs_new_blob(literal->len);
		memcpy(gen->literal.data, literal->data, literal->len);
	}

	size_t addition = 0;

	switch(kind) {
	case OBFS_TAG_BYTES:
		addition = gen->literal.len;
		break;

	case OBFS_TAG_COUNTER:
	case OBFS_TAG_TIMESTAMP:
		addition = sizeof(uint64_t);
		break;

	case OBFS_TAG_RANDOM_BYTES:
	case OBFS_TAG_RANDOM_ASCII:
	case OBFS_TAG_RANDOM_DIGIT:
		addition = (size_t)param;
		break;
	}

	def->total_size += addition;
	return true;
}

static bool obfs_compile_handshake_pattern(obfs_tag_def_t *def, const char *pattern, char **error_out) {
	if(!def || !pattern) {
		if(error_out) {
			*error_out = xstrdup("invalid handshake pattern definition");
		}
		return false;
	}

	if(error_out) {
		*error_out = NULL;
	}

	bool seen_counter = false;
	bool seen_timestamp = false;
	const char *cursor = pattern;
	bool has_entries = false;

	while(true) {
		const char *start = strchr(cursor, '<');

		if(!start) {
			break;
		}

		const char *end = strchr(start + 1, '>');

		if(!end) {
			if(error_out) {
				*error_out = xstrdup("unterminated tag in handshake pattern");
			}
			return false;
		}

		size_t token_len = (size_t)(end - (start + 1));
		char *token = xmalloc(token_len + 1);
		memcpy(token, start + 1, token_len);
		token[token_len] = '\0';

		char *trimmed = obfs_trim(token);

		if(!*trimmed) {
			free(token);
			if(error_out) {
				*error_out = xstrdup("empty handshake tag");
			}
			return false;
		}

		for(char *p = trimmed; *p; ++p) {
			if(*p == '\t') {
				*p = ' ';
			}
		}

		char *param = trimmed;
		while(*param && !isspace((unsigned char)*param)) {
			++param;
		}

		if(*param) {
			*param++ = '\0';
		}

		param = obfs_trim(param);

		for(char *p = trimmed; *p; ++p) {
			*p = (char)tolower((unsigned char)*p);
		}

		bool ok = false;

		if(!strcmp(trimmed, "b")) {
			obfs_blob_t literal = {0};

		if(!obfs_parse_hex_bytes(param, &literal)) {
			if(error_out) {
				xasprintf(error_out, "invalid hex bytes: %s", param ? param : "");
			}
				free(token);
				return false;
			}

			ok = obfs_append_generator(def, OBFS_TAG_BYTES, 0, &literal);
			obfs_free_blob(&literal);
		} else if(!strcmp(trimmed, "c")) {
			if(param && *param) {
				if(error_out) {
					*error_out = xstrdup("counter tag takes no parameters");
				}
				free(token);
				return false;
			}

			if(seen_counter) {
				if(error_out) {
					*error_out = xstrdup("counter tag may only appear once");
				}
				free(token);
				return false;
			}

			seen_counter = true;
			ok = obfs_append_generator(def, OBFS_TAG_COUNTER, 0, NULL);
		} else if(!strcmp(trimmed, "t")) {
			if(param && *param) {
				if(error_out) {
					*error_out = xstrdup("timestamp tag takes no parameters");
				}
				free(token);
				return false;
			}

			if(seen_timestamp) {
				if(error_out) {
					*error_out = xstrdup("timestamp tag may only appear once");
				}
				free(token);
				return false;
			}

			seen_timestamp = true;
			ok = obfs_append_generator(def, OBFS_TAG_TIMESTAMP, 0, NULL);
		} else if(!strcmp(trimmed, "r") || !strcmp(trimmed, "rc") || !strcmp(trimmed, "rd")) {
			unsigned int length = 0;

		if(!obfs_parse_uint(param, &length) || length == 0 || length > 1000) {
			if(error_out) {
				xasprintf(error_out, "invalid length for %s: %s", trimmed, param ? param : "");
			}
				free(token);
				return false;
			}

			obfs_tag_generator_kind_t kind = OBFS_TAG_RANDOM_BYTES;

			if(!strcmp(trimmed, "rc")) {
				kind = OBFS_TAG_RANDOM_ASCII;
			} else if(!strcmp(trimmed, "rd")) {
				kind = OBFS_TAG_RANDOM_DIGIT;
			}

			ok = obfs_append_generator(def, kind, (int)length, NULL);
	} else {
		if(error_out) {
			xasprintf(error_out, "unknown handshake tag: %s", trimmed);
		}
			free(token);
			return false;
		}

		free(token);

		if(!ok) {
			if(error_out && !*error_out) {
				*error_out = xstrdup("failed to append handshake tag");
			}
			return false;
		}

		has_entries = true;
		cursor = end + 1;
	}

	if(!has_entries) {
		if(error_out) {
			*error_out = xstrdup("handshake tag pattern produced no output");
		}
		return false;
	}

	return true;
}

void obfs_free_blob(obfs_blob_t *blob) {
	if(!blob || !blob->data) {
		return;
	}

	free(blob->data);
	blob->data = NULL;
	blob->len = 0;
}

bool obfs_is_enabled(void) {
	return obfs_config.enabled;
}

size_t obfs_header_junk_size(obfs_message_kind_t kind) {
	if(kind >= OBFS_MESSAGE_KIND_COUNT) {
		return 0;
	}

	return obfs_config.header_junk[kind];
}

int obfs_random_in_range(int min_value, int max_value) {
	if(min_value >= max_value) {
		return min_value;
	}

	int span = max_value - min_value + 1;
	uint32_t value = obfs_random_u32();
	return min_value + (value % (uint32_t)span);
}

static void obfs_fill_random_ascii(uint8_t *dest, size_t len) {
	if(!dest || !len) {
		return;
	}

	obfs_blob_t temp = obfs_new_blob(len);

	if(!temp.data) {
		return;
	}

	randomize(temp.data, temp.len);

	for(size_t i = 0; i < temp.len; ++i) {
		dest[i] = obfs_alnum_chars[temp.data[i] % (sizeof(obfs_alnum_chars) - 1)];
	}

	obfs_free_blob(&temp);
}

static void obfs_fill_random_digits(uint8_t *dest, size_t len) {
	if(!dest || !len) {
		return;
	}

	obfs_blob_t temp = obfs_new_blob(len);

	if(!temp.data) {
		return;
	}

	randomize(temp.data, temp.len);

	for(size_t i = 0; i < temp.len; ++i) {
		dest[i] = (uint8_t)('0' + (temp.data[i] % 10));
	}

	obfs_free_blob(&temp);
}

static bool obfs_emit_generators(const obfs_tag_def_t *def, uint8_t **cursor_ptr) {
	if(!def || !cursor_ptr) {
		return false;
	}

	uint8_t *cursor = *cursor_ptr;

	for(size_t j = 0; j < def->generator_count; ++j) {
		obfs_tag_generator_t *gen = &def->generators[j];

		switch(gen->kind) {
		case OBFS_TAG_BYTES:
			if(gen->literal.data && gen->literal.len) {
				memcpy(cursor, gen->literal.data, gen->literal.len);
				cursor += gen->literal.len;
			}
			break;

		case OBFS_TAG_COUNTER: {
			uint64_t value = obfs_hton64(obfs_counter_next_value());
			memcpy(cursor, &value, sizeof(value));
			cursor += sizeof(value);
			break;
		}

		case OBFS_TAG_TIMESTAMP: {
			uint64_t timestamp = (uint64_t)time(NULL);
			timestamp = obfs_hton64(timestamp);
			memcpy(cursor, &timestamp, sizeof(timestamp));
			cursor += sizeof(timestamp);
			break;
		}

		case OBFS_TAG_RANDOM_BYTES:
			randomize(cursor, (size_t)gen->param);
			cursor += (size_t)gen->param;
			break;

		case OBFS_TAG_RANDOM_ASCII:
			obfs_fill_random_ascii(cursor, (size_t)gen->param);
			cursor += (size_t)gen->param;
			break;

		case OBFS_TAG_RANDOM_DIGIT:
			obfs_fill_random_digits(cursor, (size_t)gen->param);
			cursor += (size_t)gen->param;
			break;

		default:
			return false;
		}
	}

	*cursor_ptr = cursor;
	return true;
}

obfs_blob_t obfs_create_header_junk(obfs_message_kind_t kind) {
	obfs_blob_t blob = {0};

	if(kind >= OBFS_MESSAGE_KIND_COUNT) {
		return blob;
	}

	int size = obfs_config.header_junk[kind];
	if(size <= 0) {
		return blob;
	}

	blob = obfs_new_blob((size_t)size);
	if(blob.data) {
		randomize(blob.data, blob.len);
	}

	return blob;
}

obfs_blob_t obfs_create_junk_packet(size_t payload_size) {
	obfs_blob_t blob = obfs_new_blob(payload_size);

	if(blob.data && blob.len) {
		randomize(blob.data, blob.len);
	}

	return blob;
}

uint32_t obfs_pick_magic_value(obfs_message_kind_t kind, uint32_t fallback) {
	if(kind >= OBFS_MESSAGE_KIND_COUNT) {
		return fallback;
	}

	obfs_magic_range_t *range = &obfs_config.header_magic[kind];

	if(!range->enabled) {
		return fallback;
	}

	if(range->min > range->max) {
		return fallback;
	}

	uint32_t span = range->max - range->min + 1;
	uint32_t random_value = obfs_random_u32();

	return range->min + (span ? (random_value % span) : 0);
}

void obfs_set_magic_range(obfs_message_kind_t kind, uint32_t min_value, uint32_t max_value) {
	if(kind >= OBFS_MESSAGE_KIND_COUNT) {
		return;
	}

	obfs_magic_range_t *range = &obfs_config.header_magic[kind];

	if(min_value > max_value) {
		uint32_t tmp = min_value;
		min_value = max_value;
		max_value = tmp;
	}

	range->min = min_value;
	range->max = max_value;
	range->enabled = true;
}

static obfs_tag_def_t *obfs_reserve_tag_slot(void) {
	size_t next = obfs_config.handshake_tags.count;

	if(next == obfs_config.handshake_tags.capacity) {
		size_t new_capacity = obfs_config.handshake_tags.capacity ? obfs_config.handshake_tags.capacity * 2 : 4;
		obfs_config.handshake_tags.items = xrealloc(obfs_config.handshake_tags.items, new_capacity * sizeof(*obfs_config.handshake_tags.items));

		for(size_t i = obfs_config.handshake_tags.capacity; i < new_capacity; ++i) {
			memset(&obfs_config.handshake_tags.items[i], 0, sizeof(obfs_config.handshake_tags.items[i]));
		}

		obfs_config.handshake_tags.capacity = new_capacity;
	}

	obfs_config.handshake_tags.count++;
	return &obfs_config.handshake_tags.items[next];
}

bool obfs_append_tag_definition(const char *name, const char *pattern, char **error_out) {
	if(!name || !pattern) {
		if(error_out) {
			*error_out = xstrdup("invalid tag definition");
		}
		return false;
	}

	if(error_out) {
		*error_out = NULL;
	}

	for(size_t i = 0; i < obfs_config.handshake_tags.count; ++i) {
		if(obfs_config.handshake_tags.items[i].name && !strcasecmp(obfs_config.handshake_tags.items[i].name, name)) {
			if(error_out) {
				xasprintf(error_out, "duplicate tag name: %s", name);
			}
			return false;
		}
	}

	obfs_tag_def_t *slot = obfs_reserve_tag_slot();

	slot->name = xstrdup(name);
	slot->pattern = xstrdup(pattern);

	if(!obfs_compile_handshake_pattern(slot, pattern, error_out)) {
		obfs_free_tag(slot);
		--obfs_config.handshake_tags.count;
		return false;
	}

	return true;
}

bool obfs_validate_handshake_pattern(const char *pattern, char **error_out) {
	obfs_tag_def_t temp = {0};
	bool ok = obfs_compile_handshake_pattern(&temp, pattern, error_out);
	obfs_free_tag(&temp);
	return ok;
}

obfs_message_kind_t obfs_classify_sptps_type(int type) {
	if(type == SPTPS_HANDSHAKE) {
		return OBFS_MESSAGE_INIT;
	}

	if(type == PKT_PROBE) {
		return OBFS_MESSAGE_RESPONSE;
	}

	return OBFS_MESSAGE_TRANSPORT;
}

bool obfs_choose_datagram_type(obfs_message_kind_t kind, uint8_t default_type, uint8_t *wire_type) {
	if(!wire_type) {
		return false;
	}

	*wire_type = default_type;

	if(!obfs_config.enabled || kind >= OBFS_MESSAGE_KIND_COUNT) {
		return false;
	}

	obfs_magic_range_t *range = &obfs_config.header_magic[kind];

	if(!range->enabled) {
		return false;
	}

	uint32_t candidate = obfs_pick_magic_value(kind, default_type);

	if(candidate > UINT8_MAX) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Obfs: magic header value %u exceeds 8-bit range, falling back", candidate);
		return false;
	}

	*wire_type = (uint8_t)candidate;
	return *wire_type != default_type;
}

bool obfs_strip_prefix(uint8_t **data, size_t *len, obfs_prefix_info_t *info) {
	if(info) {
		info->has_original_type = false;
		info->original_type = 0;
		info->is_junk = false;
	}

	if(!obfs_config.enabled) {
		return true;
	}

	if(!data || !*data || !len) {
		return false;
	}

	if(*len < sizeof(uint16_t)) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Obfs: received truncated datagram header (%zu bytes)", *len);
		return false;
	}

	uint8_t *cursor = *data;
	uint16_t declared_value;
	memcpy(&declared_value, cursor, sizeof(declared_value));
	uint16_t declared = ntohs(declared_value);
	cursor += sizeof(uint16_t);

	if(*len < sizeof(uint16_t) + (size_t)declared) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Obfs: junk length %u exceeds datagram size %zu", declared, *len);
		return false;
	}

	size_t remaining = declared;

	if(remaining > 0) {
		uint8_t flags = *cursor++;
		remaining--;

		if(info) {
			info->has_original_type = flags & OBFS_PREFIX_FLAG_HAS_TYPE;
			info->is_junk = flags & OBFS_PREFIX_FLAG_JUNK;
		}

		if((flags & OBFS_PREFIX_FLAG_HAS_TYPE)) {
			if(remaining == 0) {
				logger(DEBUG_TRAFFIC, LOG_WARNING, "Obfs: prefix missing stored type byte");
				return false;
			}

			uint8_t stored_type = *cursor++;
			remaining--;

			if(info) {
				info->original_type = stored_type;
			}
		}

		cursor += remaining;
		remaining = 0;
	}

	*data += sizeof(uint16_t) + declared;
	*len -= sizeof(uint16_t) + declared;
	return true;
}

size_t obfs_handshake_tag_size(void) {
	size_t total = 0;

	for(size_t i = 0; i < obfs_config.handshake_tags.count; ++i) {
		total += obfs_config.handshake_tags.items[i].total_size;
	}

	return total;
}

obfs_blob_t obfs_build_handshake_tags(void) {
	size_t total = obfs_handshake_tag_size();
	obfs_blob_t blob = obfs_new_blob(total);

	if(!blob.data || !blob.len) {
		return blob;
	}

	uint8_t *cursor = blob.data;

	for(size_t i = 0; i < obfs_config.handshake_tags.count; ++i) {
		obfs_blob_t packet = {0};

		if(!obfs_build_handshake_packet(i, &packet)) {
			obfs_free_blob(&blob);
			return (obfs_blob_t){0};
		}

		if(packet.len) {
			memcpy(cursor, packet.data, packet.len);
			cursor += packet.len;
		}

		obfs_free_blob(&packet);
	}

	return blob;
}

size_t obfs_handshake_packet_count(void) {
	return obfs_config.handshake_tags.count;
}

bool obfs_build_handshake_packet(size_t index, obfs_blob_t *out) {
	if(!out) {
		return false;
	}

	if(index >= obfs_config.handshake_tags.count) {
		*out = (obfs_blob_t){0};
		return false;
	}

	obfs_tag_def_t *def = &obfs_config.handshake_tags.items[index];
	obfs_blob_t blob = obfs_new_blob(def->total_size);

	if(def->total_size > 0) {
		if(!blob.data) {
			return false;
		}

		uint8_t *cursor = blob.data;

		if(!obfs_emit_generators(def, &cursor)) {
			obfs_free_blob(&blob);
			return false;
		}
	}

	*out = blob;
	return true;
}
