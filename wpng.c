#include <stdlib.h>

#include "wpng.h"

void wpng_error_exit(const char *msg) {
    fprintf(stderr, msg);
    fflush(stderr);
    exit(-1);
}

void wpng_init(wimg_info *wimg_ptr) {
    png_structp png_ptr;
    png_infop info_ptr;

    png_ptr =
        png_create_write_struct(PNG_LIBPNG_VER_STRING, wimg_ptr, NULL, NULL);
    if (!png_ptr) {
        wpng_error_exit("wpng_init: png_ptr\n");
    }
    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        wpng_error_exit("wpng_init: info_ptr\n");
    }

    if (setjmp(wimg_ptr->jmpbuf)) {
        wpng_error_exit("wpng_init: setjmp\n");
    }

    png_init_io(png_ptr, wimg_ptr->outfile);

    png_set_compression_level(png_ptr, 0);
    png_set_compression_strategy(png_ptr, 0);
    png_set_filter(png_ptr, 0, PNG_FILTER_NONE);

    int bit_depth = 8;
    int color_type = PNG_COLOR_TYPE_RGBA;

    png_set_user_limits(png_ptr, 1 << 30, 1 << 30);
    png_set_IHDR(png_ptr, info_ptr, wimg_ptr->width, wimg_ptr->height,
                 bit_depth, color_type, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
    png_write_info(png_ptr, info_ptr);

    wimg_ptr->png_ptr = png_ptr;
    wimg_ptr->info_ptr = info_ptr;
}

void wpng_encode_rows(wimg_info *wimg_ptr, size_t num_rows) {
    png_structp png_ptr = (png_structp)wimg_ptr->png_ptr;

    if (setjmp(wimg_ptr->jmpbuf)) {
        wpng_error_exit("wpng_encode_rows: setjmp\n");
    }

    png_write_rows(png_ptr, wimg_ptr->row_pointers, num_rows);
}

void wpng_encode_finish(wimg_info *wimg_ptr) {
    png_structp png_ptr = (png_structp)wimg_ptr->png_ptr;
    png_infop info_ptr = (png_infop)wimg_ptr->info_ptr;

    if (setjmp(wimg_ptr->jmpbuf)) {
        wpng_error_exit("wpng_encode_finish: setjmp\n");
    }

    png_write_end(png_ptr, info_ptr);
}

void wpng_cleanup(wimg_info *wimg_ptr) {
    png_structp png_ptr = (png_structp)wimg_ptr->png_ptr;
    png_infop info_ptr = (png_infop)wimg_ptr->info_ptr;

    if (png_ptr && info_ptr) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
    }

    wimg_ptr->png_ptr = NULL;
    wimg_ptr->info_ptr = NULL;

    if (wimg_ptr->outfile) {
        fclose(wimg_ptr->outfile);
        wimg_ptr->outfile = NULL;
    }

    if (wimg_ptr->row_pointers) {
        free(wimg_ptr->row_pointers);
        wimg_ptr->row_pointers = NULL;
    }
}