# Makefile: echat test program
# Author: Samuel Macpherson/Douglas Pukallus

TARGET=echat
SOURCE=echat.c

CFLAGS=-lpthread -g --std=gnu99 -pedantic -Wall

# consider clang for development but make sure it compiles in gcc as well
# uncomment to use clang as the compiler
#CC=clang

INDENT = -kr -i8 -l78 -lc79

all: $(TARGET)

$(TARGET) : $(SOURCE) 
	$(CC) $(CFLAGS) -o $@ $<

clean: 
	rm -f $(TARGET) _*

# Needs dos2unix to convert windows line endings to linux line endings
# sudo apt-get install dos2unix
indent:
	dos2unix echat.c
	indent $(INDENT) echat.c -o _echat.c

# replace echat.c indent'ed version 
merge: indent
	rename -f 's/^_//' _*

check: merge
	perl ../checkpatch-0.32.pl --no-tree --no-signoff -f --no-summary echat.c 
