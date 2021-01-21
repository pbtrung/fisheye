#include <stdlib.h>

#include "rpng.h"

void rpng_error_exit(const char *msg) {
    fprintf(stderr, msg);
    fflush(stderr);
    exit(-1);
}

void rpng_init(rimg_info *rimg_ptr) {
    png_structp png_ptr;
    png_infop info_ptr;

    png_ptr =
        png_create_read_struct(PNG_LIBPNG_VER_STRING, rimg_ptr, NULL, NULL);
    if (!png_ptr) {
        rpng_error_exit("rpng_init: png_ptr\n");
    }

    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        rpng_error_exit("rpng_init: info_ptr\n");
    }

    if (setjmp(rimg_ptr->jmpbuf)) {
        rpng_error_exit("rpng_init: setjmp\n");
    }
    png_init_io(png_ptr, rimg_ptr->infile);
    // png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);

    png_set_user_limits(png_ptr, 1 << 30, 1 << 30);
    png_read_info(png_ptr, info_ptr);
    rimg_ptr->width = png_get_image_width(png_ptr, info_ptr);
    rimg_ptr->height = png_get_image_height(png_ptr, info_ptr);
    rimg_ptr->rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    int color_type = png_get_color_type(png_ptr, info_ptr);
    int bit_depth = png_get_bit_depth(png_ptr, info_ptr);
    if (bit_depth != 8 || color_type != PNG_COLOR_TYPE_RGBA) {
        rpng_error_exit("[rpng_init] File does not have needed format\n");
    }

    rimg_ptr->png_ptr = png_ptr;
    rimg_ptr->info_ptr = info_ptr;
}

void rpng_decode_rows(rimg_info *rimg_ptr, size_t num_rows) {
    png_structp png_ptr = (png_structp)rimg_ptr->png_ptr;

    if (setjmp(rimg_ptr->jmpbuf)) {
        rpng_error_exit("rpng_decode_rows: setjmp\n");
    }

    png_read_rows(png_ptr, rimg_ptr->row_pointers, NULL, num_rows);
}

void rpng_cleanup(rimg_info *rimg_ptr) {
    png_structp png_ptr = (png_structp)rimg_ptr->png_ptr;
    png_infop info_ptr = (png_infop)rimg_ptr->info_ptr;

    if (png_ptr && info_ptr) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    }

    rimg_ptr->png_ptr = NULL;
    rimg_ptr->info_ptr = NULL;

    if (rimg_ptr->infile) {
        fclose(rimg_ptr->infile);
        rimg_ptr->infile = NULL;
    }

    if (rimg_ptr->row_pointers) {
        free(rimg_ptr->row_pointers);
        rimg_ptr->row_pointers = NULL;
    }
}
