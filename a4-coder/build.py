#!/usr/bin/python

TARGET="decoder"
DESCRIPTION="decoder for ROL3 shellcode"

import sys
import os
import binascii

if len(sys.argv) != 2:
    print "Generate a %s with a configurable payload" % DESCRIPTION
    print "Usage: %s <original.raw>" % sys.argv[0]
    sys.exit(1)

print "Building %s" % DESCRIPTION

# Read in the raw payload to be encoded
payload = ""
with open(sys.argv[1], mode='rb') as f:
    payload = f.read()

# Rotate each byte individually 3 bits to the left
encoded = ""
for i in range(len(payload)):
    x = ord(payload[i])
    # There is probably a better way to do this but it'll do
    shifted = (x << 3) & 0xff
    rotated_part = ((x << 3) & 0xff00) >> 8
    encoded += chr(shifted | rotated_part)

if "ZZZZ" in encoded:
    print "Error: Terminating string ZZZZ appears inside encoded payload"
    sys.exit(1)

# Note that decoder source takes care of appending the ZZZZ

# Prepare it for inclusion in the nasm source of the decoder
encoded_hex_string = binascii.hexlify(encoded)
encoded_hex_pairs = [encoded_hex_string[i:i+2] for i in range(0, len(encoded_hex_string), 2)]
encoded_nasm_style = ",".join(["0x" + h for h in encoded_hex_pairs])

print "Assembling..."
r = os.system("nasm -f elf32 -o %s.o -DPAYLOAD=\"%s\" %s.nasm" % (TARGET, encoded_nasm_style, TARGET))
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