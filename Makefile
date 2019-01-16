
DIR = `pwd`
SUBDIRS = `ls`
TARGET = handshake
ATHEROSPATH = /root/workspace/UGW6.0/develop/cbb/wifi/QCA/driver/qca-wifi_v5.0.3

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
CFLAGS += -I$(ATHEROSPATH)/include -I$(ATHEROSPATH)/lmac/ath_dev
CFLAGS += -I$(ATHEROSPATH)/os/linux/include

CC = /projects/hnd/tools/linux/hndtools-mips-linux-uclibc-4.9.3/usr/bin/mips-ugw-linux-uclibc-gcc
# CC = /usr/bin/gcc

all:
	@$(CC) -g $(CFLAGS) -o $(TARGET)

clean:
	@rm $(TARGET)

test:
	@echo DIR = $(DIR)
	@echo CFLAGS = $(CFLAGS)



