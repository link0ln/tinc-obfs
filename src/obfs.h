#ifndef TINC_OBFS_H
#define TINC_OBFS_H

/*
    obfs.h -- runtime configuration and helpers for traffic obfuscation
    Copyright (C) 2025

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "system.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OBFS_MESSAGE_KIND_COUNT 4

#include "net.h"
#include "sptps.h"

typedef enum {
    OBFS_MESSAGE_INIT = 0,
    OBFS_MESSAGE_RESPONSE = 1,
    OBFS_MESSAGE_COOKIE = 2,
    OBFS_MESSAGE_TRANSPORT = 3
} obfs_message_kind_t;

typedef struct {
    uint32_t min;
    uint32_t max;
    bool enabled;
} obfs_magic_range_t;

typedef struct {
    uint8_t *data;
    size_t len;
} obfs_blob_t;

typedef struct {
    bool has_original_type;
    uint8_t original_type;
    bool is_junk;
} obfs_prefix_info_t;

#define OBFS_PREFIX_FLAG_HAS_TYPE 0x01
#define OBFS_PREFIX_FLAG_JUNK 0x02

typedef enum {
    OBFS_TAG_BYTES,
    OBFS_TAG_COUNTER,
    OBFS_TAG_TIMESTAMP,
    OBFS_TAG_RANDOM_BYTES,
    OBFS_TAG_RANDOM_ASCII,
    OBFS_TAG_RANDOM_DIGIT,
} obfs_tag_generator_kind_t;

typedef struct {
    obfs_tag_generator_kind_t kind;
    int param;
    obfs_blob_t literal;
} obfs_tag_generator_t;

typedef struct {
    char *name;
    char *pattern;
    obfs_tag_generator_t *generators;
    size_t generator_count;
    size_t generator_capacity;
    size_t total_size;
} obfs_tag_def_t;

typedef struct {
    obfs_tag_def_t *items;
    size_t count;
    size_t capacity;
} obfs_tag_collection_t;

typedef struct obfs_config {
    bool enabled;
    int junk_packet_count;
    int junk_packet_min_size;
    int junk_packet_max_size;
    int header_junk[OBFS_MESSAGE_KIND_COUNT];
    obfs_magic_range_t header_magic[OBFS_MESSAGE_KIND_COUNT];
    obfs_tag_collection_t handshake_tags;
} obfs_config_t;

extern obfs_config_t obfs_config;

void obfs_init(void);
void obfs_reset(void);

/* Helpers returning freshly allocated blobs that the caller must free. */
obfs_blob_t obfs_create_header_junk(obfs_message_kind_t kind);
obfs_blob_t obfs_create_junk_packet(size_t payload_size);
void obfs_free_blob(obfs_blob_t *blob);

int obfs_random_in_range(int min_value, int max_value);
uint32_t obfs_pick_magic_value(obfs_message_kind_t kind, uint32_t fallback);

void obfs_disable_all_ranges(void);
void obfs_set_magic_range(obfs_message_kind_t kind, uint32_t min_value, uint32_t max_value);

void obfs_clear_tags(void);
bool obfs_append_tag_definition(const char *name, const char *pattern, char **error_out);
bool obfs_validate_handshake_pattern(const char *pattern, char **error_out);

bool obfs_is_enabled(void);
size_t obfs_header_junk_size(obfs_message_kind_t kind);
obfs_message_kind_t obfs_classify_sptps_type(int type);
bool obfs_choose_datagram_type(obfs_message_kind_t kind, uint8_t default_type, uint8_t *wire_type);
bool obfs_strip_prefix(uint8_t **data, size_t *len, obfs_prefix_info_t *info);
size_t obfs_handshake_tag_size(void);
obfs_blob_t obfs_build_handshake_tags(void);
size_t obfs_handshake_packet_count(void);
bool obfs_build_handshake_packet(size_t index, obfs_blob_t *out);

#endif /* TINC_OBFS_H */
