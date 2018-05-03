# fisheye

* Description: Turn an arbitrary file into an 8-bit grayscale encrypted PNG image
* Encryption: Threefish 1024-bit key in CTR mode
* Authentication: HMAC SHA3-512
* Key derivation: 42 rounds of PBKDF2 SHA3-512
* Dependencies: 
	- C version: `libsodium`, `libgcrypt`, and `libpng`
	- C++ version: `crypto++` and `libpng`
* The C++ version is faster and therefore recommended

Compile:
```
g++ main.cpp lz4.c -O3 -o fisheye -lpng -lcryptopp -Wall -Wextra -Wpedantic
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
