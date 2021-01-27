#ifndef WPNG_H
#define WPNG_H

#include <iostream>

#define PNG_DEBUG 3
#include <png.h>

typedef struct wimg_info {
    long width;
    long height;
    void *png_ptr;
    void *info_ptr;
    unsigned char **row_pointers;
    jmp_buf jmpbuf;
} wimg_info;

void wpng_init(wimg_info *wimg_ptr, std::ostream *stream);

void wpng_encode_rows(wimg_info *wimg_ptr, size_t num_rows);

void wpng_encode_finish(wimg_info *wimg_ptr);

void wpng_cleanup(wimg_info *wimg_ptr);

#endif