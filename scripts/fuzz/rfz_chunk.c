#include <stdlib.h>

#include "rfz_chunk.h"

struct rfz_chunk
rfz_get_chunk(const char *data, size_t size) {
    struct rfz_chunk chunk = {0};

    while (chunk.size < size) {
        size -= 1;
        chunk.size += (unsigned char)data[0];
        data += 1;
        if ((unsigned char)data[-1] != 255)
            break;
    }
    chunk.size += 1;
    if (chunk.size > size)
        chunk.size = size;
    chunk.data = data;
    chunk.rem_size = size - chunk.size;
    chunk.rem_data = data + chunk.size;
    return (chunk);
}
