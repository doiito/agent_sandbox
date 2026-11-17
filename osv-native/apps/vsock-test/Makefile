.PHONY: module
module: vsock-test.so task-probe.so

vsock-test.so: main.c
	$(CC) -std=gnu11 -O2 -Wall -Wextra -Werror -fPIC -shared -nostdlib \
	    -I$(OSV_BASE)/include -o $@ main.c

task-probe.so: task-probe.c
	$(CC) -std=gnu11 -O2 -Wall -Wextra -Werror -fPIC -shared -nostdlib \
	    -I$(OSV_BASE)/include -o $@ task-probe.c

clean:
	rm -f vsock-test.so task-probe.so
