#!/bin/bash
gcc decrypter.c -o decrypter -lsodium -Wall -fno-stack-protector -z execstack
