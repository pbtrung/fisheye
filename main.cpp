#include <fstream>
#include <iomanip>

#include <cryptopp/chacha.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>
using namespace CryptoPP;

#include "rpng.h"
#include "wpng.h"

static void error_exit(std::string msg) {
    std::cerr << msg << std::endl;
    exit(-1);
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
const unsigned int BLOCK_SIZE = 128;
const unsigned int X20_KEY_SIZE = 32;
const unsigned int X20_IV_SIZE = 24;
const unsigned int FILE_SIZE = 8;
const unsigned int NUM_BYTES = 4;
const unsigned int HKDF_SIZE = ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE +
                               HASH_KEY_SIZE + X20_KEY_SIZE + X20_IV_SIZE;

size_t get_file_size(std::ifstream *stream) {
    std::ifstream::pos_type old = stream->tellg();
    std::ifstream::pos_type end = stream->seekg(0, std::ios_base::end).tellg();
    stream->seekg(old);

    return static_cast<size_t>(end);
}

SecByteBlock read_key(char *keyf) {
    try {
        std::ifstream infile(keyf, std::ios::in | std::ios::binary);
        if (get_file_size(&infile) != ENC_KEY_SIZE + HASH_KEY_SIZE) {
            error_exit("[read_key] Wrong key file");
        }
        SecByteBlock key(ENC_KEY_SIZE + HASH_KEY_SIZE);
        infile.read((char *)key.data(), key.size());
        infile.close();
        return key;
    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

inline size_t div_up(size_t x, size_t y) { return x / y + !!(x % y); }

void encrypt(char *keyf, char *inf, std::ostream *stream) {
    SecByteBlock key = read_key(keyf);

    try {
        std::ifstream infile(inf, std::ios::in | std::ios::binary);
        if (!infile.is_open()) {
            error_exit("[main] infile");
        }
        size_t file_size = get_file_size(&infile);
        size_t width = ceil(
            sqrt((SALT_SIZE + BLOCK_SIZE + HASH_SIZE + file_size) / NUM_BYTES) /
            1.2);
        const size_t rowbytes = width * NUM_BYTES;
        const size_t read_size = BLOCK_SIZE * width;

        size_t num_header_rows =
            div_up(SALT_SIZE + BLOCK_SIZE + HASH_SIZE, rowbytes);
        std::vector<unsigned char> buf(num_header_rows * rowbytes);

        size_t height = num_header_rows;
        size_t remaining = file_size;
        while (remaining >= read_size) {
            height += div_up(HASH_SIZE + read_size, rowbytes);
            remaining -= read_size;
        }
        if (remaining != 0) {
            height += div_up(HASH_SIZE + remaining, rowbytes);
        }

        SecByteBlock salt(SALT_SIZE);
        OS_GenerateRandomBlock(false, salt, SALT_SIZE);
        std::memcpy(buf.data(), salt, SALT_SIZE);
        u64_to_u8(&buf[SALT_SIZE], file_size);

        SecByteBlock hkdf_hash(HKDF_SIZE);
        HKDF<SHA3_512> hkdf;
        hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(), salt,
                       salt.size(), NULL, 0);

        ConstByteArrayParameter twk(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE],
                                    TWEAK_SIZE, false);
        AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
        Threefish1024::Encryption t3f(&hkdf_hash[0], ENC_KEY_SIZE);
        t3f.SetTweak(params);
        CBC_Mode_ExternalCipher::Encryption enc(t3f, &hkdf_hash[ENC_KEY_SIZE]);

        enc.ProcessData(&buf[SALT_SIZE], &buf[SALT_SIZE], BLOCK_SIZE);

        SecByteBlock hmac_hash(HASH_SIZE);
        HMAC<SHA3_512> hmac;
        hmac.SetKey(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE],
                    HASH_KEY_SIZE);
        hmac.Update(buf.data(), SALT_SIZE + BLOCK_SIZE);
        hmac.Final(hmac_hash);
        std::memcpy(&buf[SALT_SIZE + BLOCK_SIZE], hmac_hash, HASH_SIZE);

        XChaCha20::Encryption x20;
        x20.SetKeyWithIV(
            &hkdf_hash[ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE + HASH_KEY_SIZE],
            X20_KEY_SIZE,
            &hkdf_hash[ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE + HASH_KEY_SIZE +
                       X20_KEY_SIZE],
            X20_IV_SIZE);

        if (buf.size() > SALT_SIZE + BLOCK_SIZE + HASH_SIZE) {
            x20.ProcessData(&buf[SALT_SIZE + BLOCK_SIZE + HASH_SIZE],
                            &buf[SALT_SIZE + BLOCK_SIZE + HASH_SIZE],
                            buf.size() - (SALT_SIZE + BLOCK_SIZE + HASH_SIZE));
        }

        wimg_info wpng_info;
        wpng_info.row_pointers = NULL;
        wpng_info.width = width;
        wpng_info.height = height;
        wpng_init(&wpng_info, stream);

        size_t num_rows = div_up(read_size + HASH_SIZE, rowbytes);
        wpng_info.row_pointers =
            (unsigned char **)malloc(sizeof(unsigned char *) * num_rows);
        if (wpng_info.row_pointers == NULL) {
            error_exit("[main] malloc row_pointers");
        }

        for (uint32_t i = 0; i < num_header_rows; ++i) {
            wpng_info.row_pointers[i] = buf.data() + i * rowbytes;
        }
        wpng_encode_rows(&wpng_info, num_header_rows);

        remaining = file_size;
        buf.resize(num_rows * rowbytes);
        for (uint32_t i = 0; i < num_rows; ++i) {
            wpng_info.row_pointers[i] = buf.data() + i * rowbytes;
        }

        size_t progress = 0;
        while (remaining > 0) {
            size_t req = STDMIN(remaining, read_size);
            remaining -= req;
            progress += req;

            infile.read((char *)buf.data(), req);

            req = BLOCK_SIZE * div_up(req, BLOCK_SIZE);
            enc.ProcessData(buf.data(), buf.data(), req);

            hmac.Update(buf.data(), req);
            hmac.Final(hmac_hash);

            size_t num_rows_w = div_up(req + HASH_SIZE, rowbytes);
            std::memcpy(&buf[req], hmac_hash, HASH_SIZE);
            if (num_rows_w * rowbytes > req + HASH_SIZE) {
                x20.ProcessData(&buf[req + HASH_SIZE], &buf[req + HASH_SIZE],
                                num_rows_w * rowbytes - (req + HASH_SIZE));
            }
            wpng_encode_rows(&wpng_info, num_rows_w);
            stream->flush();
            std::cerr << "\rProcessed: " << std::fixed
                      << (double)progress / file_size * 100 << "%";
        }
        std::cerr << std::endl;
        std::cerr << "Done" << std::endl;

        wpng_encode_finish(&wpng_info);
        infile.close();
        wpng_cleanup(&wpng_info);

    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

void decrypt(char *keyf, char *outf, std::istream *stream) {
    SecByteBlock key = read_key(keyf);

    try {
        rimg_info rpng_info;
        rpng_info.row_pointers = NULL;
        rpng_init(&rpng_info, stream);

        const size_t read_size = BLOCK_SIZE * rpng_info.width;
        size_t num_rows = div_up(read_size + HASH_SIZE, rpng_info.rowbytes);
        rpng_info.row_pointers =
            (unsigned char **)malloc(sizeof(unsigned char *) * num_rows);
        if (rpng_info.row_pointers == NULL) {
            error_exit("[main] malloc row_pointers");
        }

        size_t num_header_rows =
            div_up(SALT_SIZE + BLOCK_SIZE + HASH_SIZE, rpng_info.rowbytes);
        std::vector<unsigned char> buf(num_header_rows * rpng_info.rowbytes);

        for (uint32_t i = 0; i < num_header_rows; ++i) {
            rpng_info.row_pointers[i] = buf.data() + i * rpng_info.rowbytes;
        }
        rpng_decode_rows(&rpng_info, num_header_rows);

        SecByteBlock hash_from_img(HASH_SIZE);
        std::memcpy(hash_from_img, &buf[SALT_SIZE + BLOCK_SIZE], HASH_SIZE);
        SecByteBlock salt(SALT_SIZE);
        std::memcpy(salt, buf.data(), SALT_SIZE);

        SecByteBlock hkdf_hash(HKDF_SIZE);
        HKDF<SHA3_512> hkdf;
        hkdf.DeriveKey(hkdf_hash, hkdf_hash.size(), key, key.size(), salt,
                       salt.size(), NULL, 0);

        SecByteBlock hmac_hash(HASH_SIZE);
        HMAC<SHA3_512> hmac;
        hmac.SetKey(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE + TWEAK_SIZE],
                    HASH_KEY_SIZE);
        hmac.Update(buf.data(), SALT_SIZE + BLOCK_SIZE);
        hmac.Final(hmac_hash);
        if (hash_from_img != hmac_hash) {
            error_exit("[main] Wrong HMAC");
        }

        ConstByteArrayParameter twk(&hkdf_hash[ENC_KEY_SIZE + IV_SIZE],
                                    TWEAK_SIZE, false);
        AlgorithmParameters params = MakeParameters(Name::Tweak(), twk);
        Threefish1024::Decryption t3f(&hkdf_hash[0], ENC_KEY_SIZE);
        t3f.SetTweak(params);
        CBC_Mode_ExternalCipher::Decryption dec(t3f, &hkdf_hash[ENC_KEY_SIZE]);

        dec.ProcessData(&buf[SALT_SIZE], &buf[SALT_SIZE], BLOCK_SIZE);
        uint64_t file_size = u8_to_u64(&buf[SALT_SIZE]);

        size_t remaining = file_size;
        buf.resize(num_rows * rpng_info.rowbytes);
        for (uint32_t i = 0; i < num_rows; ++i) {
            rpng_info.row_pointers[i] = buf.data() + i * rpng_info.rowbytes;
        }

        std::fstream outfile(outf, std::ios::out | std::ios::binary);
        if (!outfile.is_open()) {
            error_exit("[main] outfile");
        }

        size_t progress = 0;
        while (remaining > 0) {
            size_t req = STDMIN(remaining, read_size);
            remaining -= req;
            progress += req;
            size_t write_size = req;
            req = BLOCK_SIZE * div_up(req, BLOCK_SIZE);

            size_t num_rows_w = div_up(req + HASH_SIZE, rpng_info.rowbytes);
            rpng_decode_rows(&rpng_info, num_rows_w);

            hmac.Update(buf.data(), req);
            hmac.Final(hmac_hash);

            SecByteBlock hash_from_img_w(HASH_SIZE);
            std::memcpy(hash_from_img_w, &buf[req], HASH_SIZE);
            if (hash_from_img_w != hmac_hash) {
                error_exit("[main] Wrong HMAC");
            }

            dec.ProcessData(buf.data(), buf.data(), req);
            outfile.write((char *)buf.data(), write_size);

            std::cerr << "\rProcessed: " << std::fixed
                      << (double)progress / file_size * 100 << "%";
        }
        std::cerr << std::endl;
        std::cerr << "Done" << std::endl;

        outfile.close();
        rpng_cleanup(&rpng_info);

    } catch (const Exception &ex) {
        std::cerr << ex.what() << std::endl;
        exit(-1);
    }
}

int main(int argc, char *argv[]) {

    std::cerr << std::setprecision(2);

    if (argc == 8 && strcmp(argv[1], "-k") == 0 && strcmp(argv[3], "-e") == 0 &&
        strcmp(argv[4], "-i") == 0 && strcmp(argv[6], "-o") == 0) {
        std::fstream outfile(argv[7], std::ios::out | std::ios::binary);
        if (!outfile.is_open()) {
            error_exit("[main] outfile");
        }
        encrypt(argv[2], argv[5], &outfile);
        outfile.close();

    } else if (argc == 6 && strcmp(argv[1], "-k") == 0 &&
               strcmp(argv[3], "-e") == 0 && strcmp(argv[4], "-i") == 0) {
        std::ostream &outfile = std::cout;
        encrypt(argv[2], argv[5], &outfile);

    } else if (argc == 8 && strcmp(argv[1], "-k") == 0 &&
               strcmp(argv[3], "-d") == 0 && strcmp(argv[4], "-i") == 0 &&
               strcmp(argv[6], "-o") == 0) {
        std::fstream infile(argv[5], std::ios::in | std::ios::binary);
        if (!infile.is_open()) {
            error_exit("[main] infile");
        }
        decrypt(argv[2], argv[7], &infile);
        infile.close();

    } else if (argc == 6 && strcmp(argv[1], "-k") == 0 &&
               strcmp(argv[3], "-d") == 0 && strcmp(argv[4], "-o") == 0) {
        std::istream &infile = std::cin;
        decrypt(argv[2], argv[5], &infile);

    } else {
        error_exit("[main] Wrong argv");
    }

    return 0;
}
