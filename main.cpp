#include <cryptopp/files.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>
using namespace CryptoPP;

#define PNG_DEBUG 3
#include <png.h>

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
    if (bit_depth != 8 || color_type != PNG_COLOR_TYPE_GRAY ||
        *width != *height) {
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

void write_png(char *file_name, unsigned char *data, uint32_t width,
               uint32_t height) {

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
    out[0] = (unsigned char)(x & 0xff);
    x >>= 8;
    out[1] = (unsigned char)(x & 0xff);
    x >>= 8;
    out[2] = (unsigned char)(x & 0xff);
    x >>= 8;
    out[3] = (unsigned char)(x & 0xff);
    x >>= 8;
    out[4] = (unsigned char)(x & 0xff);
    x >>= 8;
    out[5] = (unsigned char)(x & 0xff);
    x >>= 8;
    out[6] = (unsigned char)(x & 0xff);
    x >>= 8;
    out[7] = (unsigned char)(x & 0xff);
}

static inline uint64_t u8_to_u64(const unsigned char in[8U]) {
    uint64_t x;

    x = in[7];
    x <<= 8;
    x |= in[6];
    x <<= 8;
    x |= in[5];
    x <<= 8;
    x |= in[4];
    x <<= 8;
    x |= in[3];
    x <<= 8;
    x |= in[2];
    x <<= 8;
    x |= in[1];
    x <<= 8;
    x |= in[0];

    return x;
}

const unsigned int TWEAK_SIZE = 16;
const unsigned int HASH_KEY_SIZE = 64;
const unsigned int HASH_SIZE = 64;
const unsigned int SALT_SIZE = 64;
const unsigned int IV_SIZE = 128;
const unsigned int ENC_KEY_SIZE = 128;
const unsigned int FILE_SIZE = 8;
const unsigned int HKDF_SIZE =
    ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE + HASH_KEY_SIZE;
const std::string HEADER = "t3fcrypt001";
const unsigned int HEADER_SIZE = 11;

SecByteBlock read_key(char *keyf) {
    try {
        SecByteBlock key(ENC_KEY_SIZE + HASH_KEY_SIZE);
        FileSource fsource(keyf, false);
        fsource.Attach(new ArraySink(key, key.size()));
        fsource.Pump(key.size());
        return key;
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-2);
    }
}

int main(int argc, char *argv[]) {

    if (argc == 8 && strcmp(argv[1], "-k") == 0 && strcmp(argv[3], "-e") == 0 &&
        strcmp(argv[4], "-i") == 0 && strcmp(argv[6], "-o") == 0) {
        SecByteBlock key = read_key(argv[2]);

        try {
            std::ifstream ifs(argv[5], std::ios::binary | std::ios::ate);
            uint64_t file_len = ifs.tellg();

            uint32_t img_side = ceil(sqrt(HEADER_SIZE + SALT_SIZE + HASH_SIZE +
                                          FILE_SIZE + file_len));
            std::vector<unsigned char> img(img_side * img_side);

            ifs.seekg(0, std::ios::beg);
            ifs.read(
                (char *)&img[HEADER_SIZE + SALT_SIZE + HASH_SIZE + FILE_SIZE],
                file_len);
            ifs.close();

            std::memcpy(img.data(), HEADER.data(), HEADER_SIZE);
            SecByteBlock salt(SALT_SIZE);
            OS_GenerateRandomBlock(false, salt, SALT_SIZE);
            std::memcpy(&img[HEADER_SIZE], salt, SALT_SIZE);
            u64_to_u8(
                (unsigned char *)&img[HEADER_SIZE + SALT_SIZE + HASH_SIZE],
                file_len);

            SecByteBlock hkdf_hash(HKDF_SIZE);
            HKDF<SHA3_512> hkdf;
            hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(), salt,
                           salt.size(), NULL, 0);

            ConstByteArrayParameter twk(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE],
                                        TWEAK_SIZE, false);
            AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
            Threefish1024::Encryption t3f(&hkdf_hash[0], ENC_KEY_SIZE);
            t3f.SetTweak(params);
            CBC_CTS_Mode_ExternalCipher::Encryption enc(
                t3f, &hkdf_hash[ENC_KEY_SIZE]);
            size_t s = img.size() - (HEADER_SIZE + SALT_SIZE + HASH_SIZE);
            ArraySink as(&img[HEADER_SIZE + SALT_SIZE + HASH_SIZE], s);
            ArraySource(
                &img[HEADER_SIZE + SALT_SIZE + HASH_SIZE], s, true,
                new StreamTransformationFilter(enc, new Redirector(as)));

            SecByteBlock hmac_hash(HASH_SIZE);
            HMAC<SHA3_512> hmac;
            hmac.SetKey(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE],
                        HASH_KEY_SIZE);
            std::memset(&img[HEADER_SIZE + SALT_SIZE], 0, HASH_SIZE);
            hmac.Update(img.data(), img.size());
            hmac.Final(hmac_hash);
            std::memcpy(&img[HEADER_SIZE + SALT_SIZE], hmac_hash, HASH_SIZE);

            write_png(argv[7], (unsigned char *)img.data(), img_side, img_side);

        } catch (const Exception &ex) {
            std::cerr << ex.what() << std::endl;
            exit(-3);
        }

    } else if (argc == 8 && strcmp(argv[1], "-k") == 0 &&
               strcmp(argv[3], "-d") == 0 && strcmp(argv[4], "-i") == 0 &&
               strcmp(argv[6], "-o") == 0) {
        SecByteBlock key = read_key(argv[2]);

        try {
            uint32_t width, height;
            unsigned char *img = read_png(argv[5], &width, &height);
            size_t num_pixels = width * height;

            SecByteBlock hash_from_img(HASH_SIZE);
            std::memcpy(hash_from_img, &img[HEADER_SIZE + SALT_SIZE],
                        HASH_SIZE);
            SecByteBlock salt(SALT_SIZE);
            std::memcpy(salt, &img[HEADER_SIZE], SALT_SIZE);

            SecByteBlock hkdf_hash(HKDF_SIZE);
            HKDF<SHA3_512> hkdf;
            hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(), salt,
                           salt.size(), NULL, 0);

            HMAC<SHA3_512> hmac;
            hmac.SetKey(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE],
                        HASH_KEY_SIZE);
            SecByteBlock hmac_hash(HASH_SIZE);
            std::memset(&img[HEADER_SIZE + SALT_SIZE], 0, HASH_SIZE);
            hmac.Update(img, num_pixels);
            hmac.Final(hmac_hash);
            if (hash_from_img != hmac_hash) {
                std::cerr << "ERROR: HMAC" << std::endl;
                exit(-1);
            }

            ConstByteArrayParameter twk(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE],
                                        TWEAK_SIZE, false);
            AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
            Threefish1024::Decryption t3f(&hkdf_hash[0], ENC_KEY_SIZE);
            t3f.SetTweak(params);
            CBC_CTS_Mode_ExternalCipher::Decryption dec(
                t3f, &hkdf_hash[ENC_KEY_SIZE]);
            size_t s = num_pixels - (HEADER_SIZE + SALT_SIZE + HASH_SIZE);
            ArraySink as(&img[HEADER_SIZE + SALT_SIZE + HASH_SIZE], s);
            ArraySource(
                &img[HEADER_SIZE + SALT_SIZE + HASH_SIZE], s, true,
                new StreamTransformationFilter(dec, new Redirector(as)));

            uint64_t file_len =
                u8_to_u64(&img[HEADER_SIZE + SALT_SIZE + HASH_SIZE]);

            FILE *fp = fopen(argv[7], "wb");
            if (fp == NULL) {
                error_exit("[main] fopen");
            }
            if (fwrite(&img[HEADER_SIZE + SALT_SIZE + HASH_SIZE + FILE_SIZE],
                       file_len, 1, fp) < 1) {
                error_exit("[main] fwrite");
            }
            fclose(fp);

        } catch (const Exception &ex) {
            std::cerr << ex.what() << std::endl;
            exit(-3);
        }

    } else {
        error_exit("[main] Wrong argv");
    }

    return EXIT_SUCCESS;
}