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

uint32_t width, height;
png_byte color_type;
png_byte bit_depth;

static void error_exit(std::string msg, int exit_code) {
    std::cerr << msg << std::endl;
    exit(exit_code);
}

unsigned char *read_png(char *file_name) {

    unsigned char header[8];
    FILE *fp = fopen(file_name, "rb");
    if (!fp) {
        error_exit("ERROR: [read_png] 1", 1);
    }
    fread(header, 1, 8, fp);
    if (png_sig_cmp(header, 0, 8)) {
        error_exit("ERROR: [read_png] 2", 2);
    }

    png_structp png_ptr;
    png_infop info_ptr;
    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        error_exit("ERROR: [read_png] 3", 3);
    }
    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        error_exit("ERROR: [read_png] 4", 4);
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("ERROR: [read_png] 5", 5);
    }
    png_init_io(png_ptr, fp);
    png_set_sig_bytes(png_ptr, 8);

    png_read_info(png_ptr, info_ptr);
    width = png_get_image_width(png_ptr, info_ptr);
    height = png_get_image_height(png_ptr, info_ptr);
    color_type = png_get_color_type(png_ptr, info_ptr);
    bit_depth = png_get_bit_depth(png_ptr, info_ptr);
    if (bit_depth != 8 || color_type != PNG_COLOR_TYPE_GRAY || width != height) {
        error_exit("ERROR: [read_png] 17", 17);
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("ERROR: [read_png] 6", 6);
    }
    unsigned char *data = (unsigned char *)malloc(width * height);
    if (data == NULL) {
        error_exit("ERROR: [read_png] 6", 6);
    }
    png_bytep *row_pointers = NULL;
    row_pointers = (png_bytep *)malloc(sizeof(png_bytep) * height);
    if (row_pointers == NULL) {
        error_exit("ERROR: [read_png] 7", 7);
    }
    for (uint32_t i = 0; i < height; ++i) {
        row_pointers[i] = data + i * width;
    }
    png_read_image(png_ptr, row_pointers);

    fclose(fp);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    free(row_pointers);
    return data;
}

void write_png(char *file_name, unsigned char *data) {

    FILE *fp = fopen(file_name, "wb");
    if (!fp) {
        error_exit("ERROR: [write_png] 8", 8);
    }

    png_structp png_ptr;
    png_infop info_ptr;
    png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        error_exit("ERROR: [write_png] 9", 9);
    }
    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        error_exit("ERROR: [write_png] 10", 10);
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("ERROR: [write_png] 11", 11);
    }
    png_init_io(png_ptr, fp);

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("ERROR: [write_png] 12", 12);
    }
    png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
                 PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE,
                 PNG_FILTER_TYPE_BASE);
    png_write_info(png_ptr, info_ptr);

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("ERROR: [write_png] 13", 13);
    }
    png_bytep *row_pointers = NULL;
    row_pointers = (png_bytep *)malloc(sizeof(png_bytep) * height);
    if (row_pointers == NULL) {
        error_exit("ERROR: [write_png] 14", 14);
    }
    for (uint32_t i = 0; i < height; ++i) {
        row_pointers[i] = data + i * width;
    }
    png_write_image(png_ptr, row_pointers);

    if (setjmp(png_jmpbuf(png_ptr))) {
        error_exit("ERROR: [write_png] 15", 15);
    }
    png_write_end(png_ptr, info_ptr);

    png_destroy_write_struct(&png_ptr, &info_ptr);
    free(row_pointers);
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

int main(int argc, char *argv[]) {

    const unsigned int KEY_LENGTH = 128;
    const unsigned int CTR_LENGTH = 128;
    const unsigned int TWEAK_LENGTH = 16;
    const unsigned int SALT_LENGTH = 64;
    const unsigned int HSALT_LENGTH = 64;
    const unsigned int HMAC_LENGTH = 64;
    const unsigned int FILE_LENGTH = 8;
    const unsigned int HEADER_LENGTH = HMAC_LENGTH + SALT_LENGTH + HSALT_LENGTH;

    if (argc == 10 && strcmp(argv[1], "-p") == 0 && strcmp(argv[3], "-h") == 0 && strcmp(argv[5], "-i") == 0 && strcmp(argv[7], "-o") == 0 && strcmp(argv[9], "-e") == 0) {
        size_t pwd_len = strlen(argv[2]);
        assert(pwd_len >= 5);
        size_t hpwd_len = strlen(argv[4]);
        assert(hpwd_len >= 5);

        try {
            std::ifstream ifs(argv[6], std::ios::binary | std::ios::ate);
            uint64_t file_len = ifs.tellg();
            uint32_t img_side = ceil(sqrt(file_len + HEADER_LENGTH + FILE_LENGTH));
            width = height = img_side;
            std::vector<char> img_body(img_side * img_side);
            ifs.seekg(0, std::ios::beg);
            ifs.read(&img_body[HEADER_LENGTH + FILE_LENGTH], file_len);

            unsigned char salt[SALT_LENGTH];
            CryptoPP::OS_GenerateRandomBlock(false, salt, SALT_LENGTH);
            std::memcpy(&img_body[HMAC_LENGTH], salt, SALT_LENGTH);
            unsigned char hsalt[HSALT_LENGTH];
            CryptoPP::OS_GenerateRandomBlock(false, hsalt, HSALT_LENGTH);
            std::memcpy(&img_body[HMAC_LENGTH + SALT_LENGTH], hsalt, HSALT_LENGTH);
            u64_to_u8((unsigned char *)&img_body[HEADER_LENGTH], file_len);

            const unsigned int buf_len = KEY_LENGTH + CTR_LENGTH + TWEAK_LENGTH;
            CryptoPP::byte buf[buf_len];
            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_512> pbkdf2;
            pbkdf2.DeriveKey(buf, buf_len, 0, (CryptoPP::byte *)argv[2], pwd_len, salt, SALT_LENGTH, 42);

            CryptoPP::ConstByteArrayParameter tweak(&buf[KEY_LENGTH + CTR_LENGTH], TWEAK_LENGTH, false);
            CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
            CryptoPP::Threefish1024::Encryption t3f(buf, KEY_LENGTH);
            t3f.SetTweak(params);
            CryptoPP::CTR_Mode_ExternalCipher::Encryption encryptor(t3f, &buf[KEY_LENGTH]);
            encryptor.ProcessData((CryptoPP::byte *)&img_body[HEADER_LENGTH], (CryptoPP::byte *)&img_body[HEADER_LENGTH], img_body.size() - HEADER_LENGTH);

            CryptoPP::byte hkey[HMAC_LENGTH * 3];
            pbkdf2.DeriveKey(hkey, HMAC_LENGTH * 3, 0, (CryptoPP::byte *)argv[4], hpwd_len, hsalt, HSALT_LENGTH, 42);
            std::memcpy(img_body.data(), &hkey[HMAC_LENGTH * 2], HMAC_LENGTH);
            CryptoPP::HMAC<CryptoPP::SHA3_512> hmac(hkey, HMAC_LENGTH * 2);
            hmac.Update((CryptoPP::byte *)img_body.data(), img_body.size());
            CryptoPP::byte hash[HMAC_LENGTH];
            hmac.Final(hash);
            std::memcpy(img_body.data(), hash, HMAC_LENGTH);

            bit_depth = 8;
            color_type = PNG_COLOR_TYPE_GRAY;
            write_png(argv[8], (unsigned char *)img_body.data());

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
            unsigned char *img_body = read_png(argv[6]);
            size_t num_pixels = width * height;

            unsigned char hash_from_img[HMAC_LENGTH];
            std::memcpy(hash_from_img, img_body, HMAC_LENGTH);
            unsigned char hsalt[HSALT_LENGTH];
            std::memcpy(hsalt, &img_body[HMAC_LENGTH + SALT_LENGTH], HSALT_LENGTH);

            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_512> pbkdf2;
            CryptoPP::byte hkey[HMAC_LENGTH * 3];
            pbkdf2.DeriveKey(hkey, HMAC_LENGTH * 3, 0, (CryptoPP::byte *)argv[4], hpwd_len, hsalt, HSALT_LENGTH, 42);
            std::memcpy(img_body, &hkey[HMAC_LENGTH * 2], HMAC_LENGTH);
            CryptoPP::HMAC<CryptoPP::SHA3_512> hmac(hkey, HMAC_LENGTH * 2);
            hmac.Update(img_body, num_pixels);
            CryptoPP::byte hash[HMAC_LENGTH];
            hmac.Final(hash);
            if (std::memcmp(hash, hash_from_img, HMAC_LENGTH) != 0) {
                std::cerr << "ERROR: HMAC" << std::endl;
                std::cerr << "FILE : " << argv[6] << std::endl;
                exit(-1);
            }

            unsigned char salt[SALT_LENGTH];
            std::memcpy(salt, &img_body[HMAC_LENGTH], SALT_LENGTH);

            const unsigned int buf_len = KEY_LENGTH + CTR_LENGTH + TWEAK_LENGTH;
            CryptoPP::byte buf[buf_len];
            pbkdf2.DeriveKey(buf, buf_len, 0, (CryptoPP::byte *)argv[2], pwd_len, salt, SALT_LENGTH, 42);

            CryptoPP::ConstByteArrayParameter tweak(&buf[KEY_LENGTH + CTR_LENGTH], TWEAK_LENGTH, false);
            CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
            CryptoPP::Threefish1024::Encryption t3f(buf, KEY_LENGTH);
            t3f.SetTweak(params);
            CryptoPP::CTR_Mode_ExternalCipher::Encryption encryptor(t3f, &buf[KEY_LENGTH]);
            encryptor.ProcessData(&img_body[HEADER_LENGTH], &img_body[HEADER_LENGTH], num_pixels - HEADER_LENGTH);

            uint64_t file_len = u8_to_u64(&img_body[HEADER_LENGTH]);
            std::ofstream dec_image;
            dec_image.open(argv[8]);
            std::copy(&img_body[HEADER_LENGTH + FILE_LENGTH], &img_body[HEADER_LENGTH + FILE_LENGTH + file_len], std::ostream_iterator<char>(dec_image, ""));
            dec_image.close();
            free(img_body);

        } catch (CryptoPP::Exception const& ex) {
            std::cerr << "CryptoPP::Exception caught: " << ex.what() << std::endl;
            exit(-1);
        } catch (std::exception const& ex) {
            std::cerr << "std::exception caught: " << ex.what() << std::endl;
            exit(-1);
        }

    } else {
        error_exit("ERROR: Wrong argv", -1);
    }

    return EXIT_SUCCESS;
}