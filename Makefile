MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

obj-m := aids-dpi.o
aids-dpi-y := 	main.o \
				connlist.o \
				connhash.o \
				aids.o \
				proc.o \
				appinfo.o \
				packageinfo.o \
				appidmatch.o \
				connlist_timer.o \
				cJSON.o \
				rulesfile.o \
				aids_bm.o \
				http_header_id.o \
				tire.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	depmod -a;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -rf modules.order
