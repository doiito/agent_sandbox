.PHONY: module
module: pipe-stat-probe.so

pipe-stat-probe.so: main.c
	$(CC) -std=gnu11 -O2 -Wall -Wextra -Werror -fPIC -shared -nostdlib \
	    -I$(OSV_BASE)/include -o $@ main.c
