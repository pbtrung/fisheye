# fisheye

Compile:
```
gcc main.c tf1024.c tf_fast.c -I. -O3 -o fisheye -lm -lsodium -lgcrypt -lpng -Wall -Wpedantic -Wextra
```
Encrypt:
```
./fisheye -p "password" -h "HMAC key" -i a.file.name -o test.e.png -e
```
Decrypt:
```
./fisheye -p "password" -h "HMAC key" -i test.e.png -o a.file.name -d
```
