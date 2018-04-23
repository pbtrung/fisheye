# fisheye

Compile:
```
g++ main.cpp -O3 -o fisheye -lpng -lcryptopp -Wall -Wextra -Wpedantic
gcc main.c tf1024.c tf_fast.c -I. -O3 -o fisheye -lm -lsodium -lgcrypt -lpng -Wall -Wpedantic
```
Encrypt:
```
./fisheye -p "password" -h "HMAC key" -i test.png -o test.e.png -e
```
Decrypt:
```
./fisheye -p "password" -h "HMAC key" -i test.e.png -o test.d.png -d
```
