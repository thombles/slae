#!/usr/bin/python

TARGET="hunter"
DESCRIPTION="egg hunter shellcode"

import sys
import os
import socket
import binascii
import struct

if len(sys.argv) != 2:
    print "Generate %s with a configurable egg payload" % DESCRIPTION
    print "Usage: %s <egg.raw>" % sys.argv[0]
    sys.exit(1)

egg_file = sys.argv[1]

print "Building %s" % DESCRIPTION

print "Assembling..."
r = os.system("nasm -f elf32 -o %s.o %s.nasm" % (TARGET, TARGET))
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

def printable_nasm_c(data):
    hex_string = binascii.hexlify(data)
    hex_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)] 
    c = "".join(["\\x" + h for h in hex_pairs])
    nasm = ",".join(["0x" + h for h in hex_pairs])
    return (nasm, c)

raw = ""
with open("%s.raw" % TARGET, mode='rb') as f:
    raw = f.read()

egg = ""
with open(egg_file, mode='rb') as f:
    egg = f.read()

# Add the required header
egg = "\x43\x42\x41\x40\x43\x42\x41\x40" + egg

nasm_style, c_style = printable_nasm_c(raw)
egg_nasm_style, egg_c_style = printable_nasm_c(egg)
    
print "Embedding in test program shell_test.c"
with open("shell_test.c", mode='w') as f:
    f.write("#include <stdio.h>\n")
    f.write("#include <string.h>\n")
    f.write("unsigned char code[] = \"%s\";\n" % c_style)
    f.write("unsigned char egg[] = \"%s\";\n" % egg_c_style)
    f.write("int main(int argc, char *argv[]) {\n")
    f.write("    printf(\"strlen(shellcode) = %d\\n\", strlen(code));\n")
    # This should ensure that egg is in memory somewhere
    f.write("    printf(\"strlen(egg) = %d\\n\", strlen(egg));\n")
    f.write("    int (*ret)() = (int(*)())code;\n")
    f.write("    ret();\n")
    f.write("}\n")

print "Compiling test program to shell_test..."
r = os.system("gcc -fno-stack-protector -z execstack shell_test.c -o shell_test")
if r != 0:
    print "gcc returned error"
    sys.exit(1)

print "\nHUNTER"
print "\nC format:\n%s\n" % c_style
print "nasm format:\n%s\n" % nasm_style

print "EGG"
print "\nC format:\n%s\n" % egg_c_style
print "nasm format:\n%s\n" % egg_nasm_style

print "Hunter shellcode length: %d bytes" % len(raw)
if "\x00" in raw or "\x00" in egg:
    print "WARNING: Null byte is present!"
else:
    print "No nulls detected in either output."
