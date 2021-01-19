#ifndef RPNG_H
#define RPNG_H

#define PNG_DEBUG 3
#include <png.h>

typedef struct rimg_info {
    long width;
    long height;
    void *png_ptr;
    void *info_ptr;
    FILE *infile;
    unsigned char **row_pointers;
    jmp_buf jmpbuf;
} rimg_info;

void rpng_init(rimg_info *rimg_ptr);

void rpng_decode_rows(rimg_info *rimg_ptr, size_t num_rows);

void rpng_cleanup(rimg_info *rimg_ptr);

#endif