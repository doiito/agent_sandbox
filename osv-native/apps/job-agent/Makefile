.PHONY: module
module: osv-job-agent.so task-probe.so

osv-job-agent.so: main.c pristine.h pristine-inputs.h completion.h $(OSV_BASE)/include/osv/input-files.h $(OSV_BASE)/include/osv/sandbox-input.h
	$(CC) -std=gnu11 -O2 -Wall -Wextra -Werror -fPIC -shared -nostdlib \
	    -I$(OSV_BASE)/include -o $@ main.c

task-probe.so: $(OSV_BASE)/apps/vsock-test/task-probe.c
	$(CC) -std=gnu11 -O2 -Wall -Wextra -Werror -fPIC -shared -nostdlib \
	    -I$(OSV_BASE)/include -o $@ $<

clean:
	rm -f osv-job-agent.so task-probe.so
