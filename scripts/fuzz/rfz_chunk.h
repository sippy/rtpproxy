#pragma once

struct rfz_chunk {
    size_t size;
    const char *data;
    size_t rem_size;
    const char *rem_data;
};

struct rfz_chunk rfz_get_chunk(const char *, size_t);
