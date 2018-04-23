# fisheye

Compile:
```
g++ main.cpp -O3 -o imgenc -lpng -lcryptopp -Wall -Wextra -Wpedantic
```
Encrypt:
```
./imgenc -p "password" -h "HMAC key" -i test.png -o test.e.png -e
```
Decrypt:
```
./imgenc -p "password" -h "HMAC key" -i test.e.png -o test.d.png -d
```
