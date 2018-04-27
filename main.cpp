#include <cassert>
#include <cstring>
#include <cmath>

#include <fstream>
#include <iterator>
#include <iostream>

#include <cryptopp/modes.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>
#include <cryptopp/osrng.h>

#define PNG_DEBUG 3
#include <png.h>

#include "lz4.h"

static void error_exit(std::string msg) {
    std::cerr << msg << std::endl;
    exit(-1);
}

unsigned char *read_png(char *file_name, uint32_t *width, uint32_t *height) {

    unsigned char header[8];
    FILE *fp = fopen(file_name, "rb");
    if (fp == NULL) {
        error_exit("[read_png] fopen");
    }
    if (fread(header, 1, 8, fp) < 8) {
        error_exit("[read_png] fread");
    }
    if (png_sig_cmp(header, 0, 8) != 0) {
        error_exit("[read_png] png_sig_cmp");
    }

    png_structp png_ptr;
    png_infop info_ptr;
    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png_ptr == NULL) {
        error_exit("[read_png] png_create_read_struct");
    }
    info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL) {
        error_exit("[read_png] png_create_info_struct");
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("[read_png] png_init_io");
    }
    png_init_io(png_ptr, fp);
    png_set_sig_bytes(png_ptr, 8);

    png_read_info(png_ptr, info_ptr);
    *width = png_get_image_width(png_ptr, info_ptr);
    *height = png_get_image_height(png_ptr, info_ptr);
    int color_type = png_get_color_type(png_ptr, info_ptr);
    int bit_depth = png_get_bit_depth(png_ptr, info_ptr);
    if (bit_depth != 8 || color_type != PNG_COLOR_TYPE_GRAY || *width != *height) {
        error_exit("[read_png] File does not have needed format");
    }

    unsigned char *data = (unsigned char *)malloc(*width * *height);
    if (data == NULL) {
        error_exit("[read_png] Unable to allocate memory");
    }
    png_bytep *row_pointers = NULL;
    row_pointers = (png_bytep *)malloc(sizeof(png_bytep) * *height);
    if (row_pointers == NULL) {
        error_exit("[read_png] Unable to allocate memory");
    }
    for (uint32_t i = 0; i < *height; ++i) {
        row_pointers[i] = data + i * *width;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("[read_png] png_read_image");
    }
    png_read_image(png_ptr, row_pointers);
    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("[read_png] png_read_end");
    }
    png_read_end(png_ptr, NULL);

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    fclose(fp);
    free(row_pointers);
    row_pointers = NULL;

    return data;
}

void write_png(char *file_name, unsigned char *data, uint32_t width, uint32_t height) {

    FILE *fp = fopen(file_name, "wb");
    if (fp == NULL) {
        error_exit("[write_png] fopen");
    }

    png_structp png_ptr;
    png_infop info_ptr;
    png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png_ptr == NULL) {
        error_exit("[write_png] png_create_write_struct");
    }
    info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL) {
        error_exit("[write_png] png_create_info_struct");
    }

    png_set_compression_level(png_ptr, 0);
    png_set_compression_strategy(png_ptr, 0);
    png_set_filter(png_ptr, 0, PNG_FILTER_NONE);

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("[write_png] png_init_io");
    }
    png_init_io(png_ptr, fp);

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("[write_png] png_write_info");
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
        error_exit("[write_png] Unable to allocate memory");
    }
    for (uint32_t i = 0; i < height; ++i) {
        row_pointers[i] = data + i * width;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("[write_png] png_write_image");
    }
    png_write_image(png_ptr, row_pointers);
    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("[write_png] png_write_end");
    }
    png_write_end(png_ptr, NULL);

    png_destroy_write_struct(&png_ptr, &info_ptr);
    free(row_pointers);
    row_pointers = NULL;
    fclose(fp);
}

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

const unsigned int KEY_LENGTH = 128;
const unsigned int CTR_LENGTH = 128;
const unsigned int TWEAK_LENGTH = 16;
const unsigned int SALT_LENGTH = 64;
const unsigned int HSALT_LENGTH = 64;
const unsigned int HMAC_LENGTH = 64;
const unsigned int FILE_LENGTH = 8;
const unsigned int COMPRESSED_LENGTH = 8;
const unsigned int ENC_KEY_LENGTH = KEY_LENGTH + CTR_LENGTH + TWEAK_LENGTH;
const unsigned int HEADER_LENGTH = HMAC_LENGTH + SALT_LENGTH + HSALT_LENGTH;

static void hmac(unsigned char *data, size_t data_len, char *hpwd, size_t hpwd_len, unsigned char *hsalt, size_t hsalt_len) {
    CryptoPP::byte hkey[HMAC_LENGTH * 3];
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_512> pbkdf2;
    pbkdf2.DeriveKey(hkey, HMAC_LENGTH * 3, 0, (CryptoPP::byte *)hpwd, hpwd_len, hsalt, hsalt_len, 42);
    
    std::memcpy(data, &hkey[HMAC_LENGTH * 2], HMAC_LENGTH);
    CryptoPP::HMAC<CryptoPP::SHA3_512> hmac(hkey, HMAC_LENGTH * 2);
    hmac.Update(data, data_len);
    CryptoPP::byte hmac_hash[HMAC_LENGTH];
    hmac.Final(hmac_hash);
    std::memcpy(data, hmac_hash, HMAC_LENGTH);
}

static void t3f_ctr(unsigned char *data, size_t data_len, char *pwd, size_t pwd_len, unsigned char *salt, size_t salt_len) {
    CryptoPP::byte buf[ENC_KEY_LENGTH];
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_512> pbkdf2;
    pbkdf2.DeriveKey(buf, ENC_KEY_LENGTH, 0, (CryptoPP::byte *)pwd, pwd_len, salt, salt_len, 42);

    CryptoPP::ConstByteArrayParameter tweak(&buf[KEY_LENGTH + CTR_LENGTH], TWEAK_LENGTH, false);
    CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
    CryptoPP::Threefish1024::Encryption t3f(buf, KEY_LENGTH);
    t3f.SetTweak(params);
    CryptoPP::CTR_Mode_ExternalCipher::Encryption encryptor(t3f, &buf[KEY_LENGTH]);
    encryptor.ProcessData(data, data, data_len);
}

int main(int argc, char *argv[]) {

    if (argc == 10 && strcmp(argv[1], "-p") == 0 && strcmp(argv[3], "-h") == 0 && strcmp(argv[5], "-i") == 0 && strcmp(argv[7], "-o") == 0 && strcmp(argv[9], "-e") == 0) {
        size_t pwd_len = strlen(argv[2]);
        assert(pwd_len >= 5);
        size_t hpwd_len = strlen(argv[4]);
        assert(hpwd_len >= 5);

        try {
            std::ifstream ifs(argv[6], std::ios::binary | std::ios::ate);
            uint64_t file_len = ifs.tellg();
            char *raw_file = (char *)malloc(file_len);
            if (raw_file == NULL) {
                error_exit("[main] Unable to allocate memory");
            }
            ifs.seekg(0, std::ios::beg);
            ifs.read(raw_file, file_len);

            size_t max_compressed_size = LZ4_compressBound(file_len);
            unsigned char *compressed_buf = (unsigned char *)malloc(max_compressed_size);
            if (compressed_buf == NULL) {
                error_exit("[main] Unable to allocate memory");
            }
            uint64_t compressed_size = LZ4_compress_default(raw_file, (char *)compressed_buf, file_len, max_compressed_size);
            if (compressed_size == 0) {
                error_exit("[main] LZ4_compress_default");
            }
            free(raw_file);
            raw_file = NULL;

            uint32_t img_side = ceil(sqrt(HEADER_LENGTH + FILE_LENGTH + COMPRESSED_LENGTH + compressed_size));
            std::vector<char> img_body(img_side * img_side);
            std::memcpy(&img_body[HEADER_LENGTH + FILE_LENGTH + COMPRESSED_LENGTH], compressed_buf, compressed_size);
            free(compressed_buf);
            compressed_buf = NULL;

            unsigned char salt[SALT_LENGTH];
            CryptoPP::OS_GenerateRandomBlock(false, salt, SALT_LENGTH);
            std::memcpy(&img_body[HMAC_LENGTH], salt, SALT_LENGTH);
            unsigned char hsalt[HSALT_LENGTH];
            CryptoPP::OS_GenerateRandomBlock(false, hsalt, HSALT_LENGTH);
            std::memcpy(&img_body[HMAC_LENGTH + SALT_LENGTH], hsalt, HSALT_LENGTH);
            u64_to_u8((unsigned char *)&img_body[HEADER_LENGTH], file_len);
            u64_to_u8((unsigned char *)&img_body[HEADER_LENGTH + FILE_LENGTH], compressed_size);

            t3f_ctr((unsigned char *)&img_body[HEADER_LENGTH], img_body.size() - HEADER_LENGTH, argv[2], pwd_len, salt, SALT_LENGTH);
            hmac((CryptoPP::byte *)img_body.data(), img_body.size(), argv[4], hpwd_len, hsalt, HSALT_LENGTH);

            write_png(argv[8], (unsigned char *)img_body.data(), img_side, img_side);

        } catch (CryptoPP::Exception const& ex) {
            std::cerr << "CryptoPP::Exception caught: " << ex.what() << std::endl;
            exit(-1);
        } catch (std::exception const& ex) {
            std::cerr << "std::exception caught: " << ex.what() << std::endl;
            exit(-1);
        }

    } else if (argc == 10 && strcmp(argv[1], "-p") == 0 && strcmp(argv[3], "-h") == 0 && strcmp(argv[5], "-i") == 0 && strcmp(argv[7], "-o") == 0 && strcmp(argv[9], "-d") == 0) {
        size_t pwd_len = strlen(argv[2]);
        assert(pwd_len >= 5);
        size_t hpwd_len = strlen(argv[4]);
        assert(hpwd_len >= 5);

        try {
            uint32_t width, height;
            unsigned char *img_body = read_png(argv[6], &width, &height);
            size_t num_pixels = width * height;

            unsigned char hash_from_img[HMAC_LENGTH];
            std::memcpy(hash_from_img, img_body, HMAC_LENGTH);
            unsigned char hsalt[HSALT_LENGTH];
            std::memcpy(hsalt, &img_body[HMAC_LENGTH + SALT_LENGTH], HSALT_LENGTH);

            hmac(img_body, num_pixels, argv[4], hpwd_len, hsalt, HSALT_LENGTH);
            if (std::memcmp(img_body, hash_from_img, HMAC_LENGTH) != 0) {
                std::cerr << "ERROR: HMAC" << std::endl;
                std::cerr << "FILE : " << argv[6] << std::endl;
                exit(-1);
            }

            unsigned char salt[SALT_LENGTH];
            std::memcpy(salt, &img_body[HMAC_LENGTH], SALT_LENGTH);

            t3f_ctr(&img_body[HEADER_LENGTH], num_pixels - HEADER_LENGTH, argv[2], pwd_len, salt, SALT_LENGTH);

            uint64_t file_len = u8_to_u64(&img_body[HEADER_LENGTH]);
            uint64_t compressed_size = u8_to_u64(&img_body[HEADER_LENGTH + FILE_LENGTH]);
            unsigned char *decompressed_buf = (unsigned char *)malloc(file_len);
            if (decompressed_buf == NULL) {
                error_exit("[main] Unable to allocate memory");
            }
            uint64_t decompressed_size = LZ4_decompress_safe((char *)&img_body[HEADER_LENGTH + FILE_LENGTH + COMPRESSED_LENGTH], (char *)decompressed_buf, compressed_size, file_len);
            if (decompressed_size <= 0 || decompressed_size != file_len) {
                error_exit("[main] LZ4_decompress_safe");
            }
            free(img_body);

            std::ofstream dec_file;
            dec_file.open(argv[8]);
            std::copy(decompressed_buf, decompressed_buf + decompressed_size, std::ostream_iterator<char>(dec_file, ""));
            dec_file.close();
            free(decompressed_buf);

        } catch (CryptoPP::Exception const& ex) {
            std::cerr << "CryptoPP::Exception caught: " << ex.what() << std::endl;
            exit(-1);
        } catch (std::exception const& ex) {
            std::cerr << "std::exception caught: " << ex.what() << std::endl;
            exit(-1);
        }

    } else {
        error_exit("[main] Wrong argv");
    }

    return EXIT_SUCCESS;
}