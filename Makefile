
DIR = `pwd`
SUBDIRS = `ls`
TARGET = handshake

CFLAGS = main.c \
	$(DIR)/crypto/sha1.c \
	$(DIR)/crypto/sha1-internal.c \
	$(DIR)/crypto/md5.c \
	$(DIR)/crypto/md5-internal.c \
	$(DIR)/crypto/random.c \
	$(DIR)/crypto/rc4.c \
	$(DIR)/crypto/aes-unwrap.c \
	$(DIR)/crypto/aes-internal-dec.c \
	$(DIR)/crypto/aes-internal.c \
	$(DIR)/crypto/sha1-prf.c \
	$(DIR)/crypto/sha1-pbkdf2.c \
	$(DIR)/utils/os_unix.c \
	$(DIR)/utils/common.c \
	$(DIR)/utils/wpa_debug.c \
	$(DIR)/rsn_supp/wpa.c \
	$(DIR)/rsn_supp/wpa_ie.c \
	$(DIR)/common/wpa_common.c

CFLAGS += -I$(DIR) -I$(DIR)/utils  -I$(DIR)/crypto -I$(DIR)/common -I$(DIR)/l2_packet -I$(DIR)/rsn_supp -I$(DIR)/eap_common -I$(DIR)/eapol_supp

# CC = /projects/hnd/tools/linux/hndtools-mips-linux-uclibc-4.9.3/usr/bin/mips-ugw-linux-uclibc-gcc
CC = /usr/bin/gcc

all:
	@$(CC) -g $(CFLAGS) -o $(TARGET)

clean:
	# for dir in $(SUBDIRS); do \
	# if [ -d $$dir ] ; then \
		# if [ -f $$dir/Makefile ] ; then \
			# $(MAKE) -C $$dir clean; \
		# fi \
	# fi \
	# done
	@rm $(TARGET)

test:
	@echo DIR = $(DIR)
	@echo CFLAGS = $(CFLAGS)