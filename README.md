# fisheye

* Description: Turn an arbitrary file into an 8-bit grayscale encrypted PNG image
* Encryption: Threefish 1024-bit key in CTR mode
* Authentication: HMAC SHA3-512
* Key derivation: 42 rounds of PBKDF2 SHA3-512
* Dependencies: `libsodium`, `libgcrypt`, and `libpng`

Compile:
```
gcc main.c tf1024.c tf_fast.c lz4.c -I. -O3 -o fisheye -lm -lsodium -lgcrypt -lpng -Wall -Wpedantic -Wextra
```
Encrypt:
```
./fisheye -p "password" -h "HMAC key" -i a.file.name -o test.e.png -e
```
Decrypt:
```
./fisheye -p "password" -h "HMAC key" -i test.e.png -o a.file.name -d
```
