#include <assert.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>
#include <sodium.h>

#define PNG_DEBUG 3
#include <png.h>

#include "tf1024.h"

void abort_(const char *s, ...) {
    va_list args;
    va_start(args, s);
    vfprintf(stderr, s, args);
    fprintf(stderr, "\n");
    va_end(args);
    abort();
}

unsigned char *read_png(char *file_name, uint32_t *width, uint32_t *height) {

    unsigned char header[8];
    FILE *fp = fopen(file_name, "rb");
    if (fp == NULL) {
        abort_("[read_png] File %s could not be opened for reading", file_name);
    }
    if (fread(header, 1, 8, fp) < 8) {
	    abort_("[read_png] File %s could not be read", file_name);
	}
    if (png_sig_cmp(header, 0, 8)) {
        abort_("[read_png] File %s is not a PNG image", file_name);
    }

    png_structp png_ptr;
    png_infop info_ptr;
    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        abort_("[read_png] png_create_read_struct failed");
    }
    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        abort_("[read_png] png_create_info_struct failed");
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        abort_("[read_png] png_init_io failed");
    }
    png_init_io(png_ptr, fp);
    png_set_sig_bytes(png_ptr, 8);

    png_read_info(png_ptr, info_ptr);
    *width = png_get_image_width(png_ptr, info_ptr);
    *height = png_get_image_height(png_ptr, info_ptr);
    int color_type = png_get_color_type(png_ptr, info_ptr);
    int bit_depth = png_get_bit_depth(png_ptr, info_ptr);
    if (bit_depth != 8 || color_type != PNG_COLOR_TYPE_GRAY || *width != *height) {
        abort_("[read_png] File %s does not have needed format", file_name);
    }

    unsigned char *data = malloc(*width * *height);
    if (data == NULL) {
        abort_("[read_png] Unable to allocate memory");
    }
    png_bytep *row_pointers = NULL;
    row_pointers = (png_bytep *)malloc(sizeof(png_bytep) * *height);
    if (row_pointers == NULL) {
        abort_("[read_png] Unable to allocate memory");
    }
    for (uint32_t i = 0; i < *height; ++i) {
        row_pointers[i] = data + i * *width;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        abort_("[read_png] png_read_image failed");
    }
    png_read_image(png_ptr, row_pointers);
    if (setjmp(png_jmpbuf(png_ptr))) {
        abort_("[read_png] png_read_end failed");
    }
    png_read_end(png_ptr, NULL);

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    fclose(fp);
    free(row_pointers);
    return data;
}

void write_png(char *file_name, unsigned char *data, uint32_t width, uint32_t height) {

    FILE *fp = fopen(file_name, "wb");
    if (!fp) {
        abort_("[write_png] File %s could not be opened for writing", file_name);
    }

    png_structp png_ptr;
    png_infop info_ptr;
    png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        abort_("[write_png] png_create_write_struct failed");
    }
    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        abort_("[write_png] png_create_info_struct failed");
    }

    png_set_compression_level(png_ptr, 0);
    png_set_compression_strategy(png_ptr, 0);
    png_set_filter(png_ptr, 0, PNG_FILTER_NONE);
    
    if (setjmp(png_jmpbuf(png_ptr))) {
        abort_("[write_png] png_init_io failed");
    }
    png_init_io(png_ptr, fp);

    if (setjmp(png_jmpbuf(png_ptr))) {
        abort_("[write_png] png_write_info failed");
    }
    int bit_depth = 8;
    int color_type = PNG_COLOR_TYPE_GRAY;
    png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
                 PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE,
                 PNG_FILTER_TYPE_BASE);
    png_write_info(png_ptr, info_ptr);

    png_bytep *row_pointers = NULL;
    row_pointers = (png_bytep *)malloc(sizeof(png_bytep) * height);
    if (row_pointers == NULL) {
        abort_("[write_png] Unable to allocate memory");
    }
    for (uint32_t i = 0; i < height; ++i) {
        row_pointers[i] = data + i * width;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        abort_("[write_png] png_write_image failed");
    }
    png_write_image(png_ptr, row_pointers);
    if (setjmp(png_jmpbuf(png_ptr))) {
        abort_("[write_png] png_write_end failed");
    }
    png_write_end(png_ptr, info_ptr);

    png_destroy_write_struct(&png_ptr, &info_ptr);
    free(row_pointers);
    fclose(fp);
}

#define KEY_LENGTH 128U
#define CTR_LENGTH 128U
#define TWEAK_LENGTH 16U
#define SALT_LENGTH 64U
#define HSALT_LENGTH 64U
#define HMAC_LENGTH 64U
#define FILE_LENGTH 8U
#define HEADER_LENGTH (HMAC_LENGTH + SALT_LENGTH + HSALT_LENGTH)

static inline void u64_to_u8(unsigned char out[8U], uint64_t x) {
    out[0] = (unsigned char) (x & 0xff); x >>= 8;
    out[1] = (unsigned char) (x & 0xff); x >>= 8;
    out[2] = (unsigned char) (x & 0xff); x >>= 8;
    out[3] = (unsigned char) (x & 0xff); x >>= 8;
    out[4] = (unsigned char) (x & 0xff); x >>= 8;
    out[5] = (unsigned char) (x & 0xff); x >>= 8;
    out[6] = (unsigned char) (x & 0xff); x >>= 8;
    out[7] = (unsigned char) (x & 0xff);
}

static inline uint64_t u8_to_u64(const unsigned char in[8U]) {
    uint64_t x;

    x  = in[7]; x <<= 8;
    x |= in[6]; x <<= 8;
    x |= in[5]; x <<= 8;
    x |= in[4]; x <<= 8;
    x |= in[3]; x <<= 8;
    x |= in[2]; x <<= 8;
    x |= in[1]; x <<= 8;
    x |= in[0];

    return x;
}

static void compute_hmac(unsigned char *hmac_key, size_t hmac_key_len,
                         unsigned char *msg, size_t msg_len,
                         unsigned char *hash, size_t *hash_len) {
    assert(hmac_key != NULL);
    assert(msg != NULL);
    assert(hash != NULL);
    assert(*hash_len >= HMAC_LENGTH);

    gcry_mac_hd_t hd;
    gcry_error_t err = gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA3_512, GCRY_MAC_FLAG_SECURE, NULL);
    if (err) {
        abort_("[compute_hmac] Error: gcry_mac_open");
    }
    err = gcry_mac_setkey(hd, hmac_key, hmac_key_len);
    if (err) {
        abort_("[compute_hmac] Error: gcry_mac_setkey");
    }
    err = gcry_mac_write(hd, msg, msg_len);
    if (err) {
        abort_("[compute_hmac] Error: gcry_mac_write");
    }
    err = gcry_mac_read(hd, hash, hash_len);
    if (err) {
        abort_("[compute_hmac] Error: gcry_mac_read");
    }
    if (*hash_len != HMAC_LENGTH) {
        abort_("[compute_hmac] Error: hash_len != HMAC_LENGTH");
    }
    gcry_mac_close(hd);
}

static void key_derive(char *pass, size_t pwd_len, unsigned char *salt,
                       size_t salt_len, unsigned char *enc_key,
                       size_t key_len) {
    assert(pass != NULL);
    assert(salt != NULL);
    assert(enc_key != NULL);
    assert(key_len >= KEY_LENGTH);
    assert(salt_len >= SALT_LENGTH);

    gcry_error_t err = gcry_kdf_derive(pass, pwd_len, GCRY_KDF_PBKDF2, GCRY_MD_SHA3_512, salt,
                        			   salt_len, 42, key_len, enc_key);
    if (err) {
        abort_("[key_derive] Error: gcry_kdf_derive");
    }
}

static void ctr(char *pass, size_t pwd_len, unsigned char *salt,
                size_t salt_len, unsigned char *in, size_t in_len) {
    assert(pass != NULL);
    assert(salt != NULL);
    assert(in != NULL);
    assert(salt_len >= SALT_LENGTH);

    size_t enc_key_len = KEY_LENGTH + CTR_LENGTH + TWEAK_LENGTH;
    unsigned char enc_key[enc_key_len];
    key_derive(pass, pwd_len, salt, salt_len, enc_key, enc_key_len);
    tf1024_ctx tf_ctx;
    tf1024_init(&tf_ctx);
    tfc1024_set_key(&tf_ctx.tfc, enc_key, KEY_LENGTH);
    tfc1024_set_tweak(&tf_ctx.tfc, &enc_key[KEY_LENGTH + CTR_LENGTH]);
    tf1024_start_counter(&tf_ctx, &enc_key[KEY_LENGTH]);
    tf1024_crypt(&tf_ctx, in, in_len, in);
    tf1024_done(&tf_ctx);
}

int main(int argc, char **argv) {

    if (sodium_init() < 0) {
        abort_("[sodium_init] Error");
    }

    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (argc == 10 && strcmp(argv[1], "-p") == 0 &&
        strcmp(argv[3], "-h") == 0 && strcmp(argv[5], "-i") == 0 &&
        strcmp(argv[7], "-o") == 0 && strcmp(argv[9], "-e") == 0) {

        size_t pwd_len = strlen(argv[2]);
        assert(pwd_len >= 5);
        size_t hpwd_len = strlen(argv[4]);
        assert(hpwd_len >= 5);

        FILE *infile = fopen(argv[6], "rb");
        if (infile == NULL) {
            abort_("[main] File %s could not be opened for reading", argv[6]);
        }
        fseek(infile, 0, SEEK_END);
        uint64_t fsize = ftell(infile);
        fseek(infile, 0, SEEK_SET);

        size_t img_side = ceil(sqrt(fsize + HEADER_LENGTH + FILE_LENGTH));
        size_t num_pixels = img_side * img_side;
        unsigned char *img_data = malloc(num_pixels);
        if (img_data == NULL) {
            abort_("[main] Unable to allocate memory");
        }
        size_t nread = fread(&img_data[HEADER_LENGTH + FILE_LENGTH], fsize, 1, infile);
        if (nread < fsize && ferror(infile)) {
            abort_("[main] Unable to read file");
        }
        fclose(infile);

        u64_to_u8(&img_data[HEADER_LENGTH], fsize);

        unsigned char salt[SALT_LENGTH];
        randombytes_buf(salt, SALT_LENGTH);
        memcpy(&img_data[HMAC_LENGTH], salt, SALT_LENGTH);
        unsigned char hsalt[HSALT_LENGTH];
        randombytes_buf(hsalt, HSALT_LENGTH);
        memcpy(&img_data[HMAC_LENGTH + SALT_LENGTH], hsalt, HSALT_LENGTH);

        ctr(argv[2], pwd_len, salt, SALT_LENGTH, &img_data[HEADER_LENGTH], num_pixels - HEADER_LENGTH);

        unsigned char hmac_key[HMAC_LENGTH * 3];
        key_derive(argv[4], hpwd_len, hsalt, HSALT_LENGTH, hmac_key, HMAC_LENGTH * 3);
        memcpy(img_data, &hmac_key[HMAC_LENGTH * 2], HMAC_LENGTH);
        size_t hmac_len = HMAC_LENGTH;
        compute_hmac(hmac_key, HMAC_LENGTH * 2, img_data, num_pixels, img_data, &hmac_len);

        write_png(argv[8], img_data, img_side, img_side);
        free(img_data);

    } else if (argc == 10 && strcmp(argv[1], "-p") == 0 &&
               strcmp(argv[3], "-h") == 0 && strcmp(argv[5], "-i") == 0 &&
               strcmp(argv[7], "-o") == 0 && strcmp(argv[9], "-d") == 0) {

        size_t pwd_len = strlen(argv[2]);
        assert(pwd_len >= 5);
        size_t hpwd_len = strlen(argv[4]);
        assert(hpwd_len >= 5);

        uint32_t width, height;
        unsigned char *img_data = read_png(argv[6], &width, &height);

        unsigned char salt[SALT_LENGTH];
        memcpy(salt, &img_data[HMAC_LENGTH], SALT_LENGTH);
        unsigned char hsalt[HSALT_LENGTH];
        memcpy(hsalt, &img_data[HMAC_LENGTH + SALT_LENGTH], HSALT_LENGTH);
        unsigned char hash_from_img[HMAC_LENGTH];
        memcpy(hash_from_img, img_data, HMAC_LENGTH);

        size_t num_pixels = width * height;
        unsigned char hmac_key[HMAC_LENGTH * 3];
        key_derive(argv[4], hpwd_len, hsalt, HSALT_LENGTH, hmac_key, HMAC_LENGTH * 3);
        memcpy(img_data, &hmac_key[HMAC_LENGTH * 2], HMAC_LENGTH);
        size_t hmac_len = HMAC_LENGTH;
        compute_hmac(hmac_key, HMAC_LENGTH * 2, img_data, num_pixels, img_data, &hmac_len);
        if (memcmp(hash_from_img, img_data, HMAC_LENGTH) != 0) {
            abort_("[main] Error: HMAC");
        }

        ctr(argv[2], pwd_len, salt, SALT_LENGTH, &img_data[HEADER_LENGTH], num_pixels - HEADER_LENGTH);

        uint64_t fsize = u8_to_u64(&img_data[HEADER_LENGTH]);
        FILE *fp = fopen(argv[8], "wb");
        if (fp == NULL) {
            abort_("[main] File %s could not be opened for writing", argv[8]);
        }
        if (fwrite(&img_data[HEADER_LENGTH + FILE_LENGTH], fsize, 1, fp) < 1) {
            abort_("[main] Error: Unable to write to file");
        }
        fclose(fp);
        free(img_data);

    } else {
        abort_("[main] Wrong argv");
    }

    return EXIT_SUCCESS;
}