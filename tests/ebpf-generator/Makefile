.PHONY: all run clean

all:
	rm -rf workdir
	mkdir -p workdir
	cp generated/Makefile workdir/Makefile
	cp generated/load.sh workdir/load.sh
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > workdir/vmlinux.h
	sudo /usr/local/go/bin/go run . --mode uniform

run:
	/usr/local/go/bin/go run .

clean:
	rm -rf workdir
	mkdir -p workdir
	cp generated/Makefile workdir/Makefile
	sudo cp generated/load.sh workdir/load.sh
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > workdir/vmlinux.h
