.PHONY: module
module: input-mount-test.so

input-mount-test.so: main.c $(OSV_BASE)/include/osv/sandbox-input.h $(OSV_BASE)/include/osv/input-files.h
	$(CC) -std=gnu11 -O2 -Wall -Wextra -Werror -fPIC -shared -nostdlib \
	    -I$(OSV_BASE)/include -o $@ main.c
