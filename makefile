CC    = ppc-amigaos-gcc
STRIP = ppc-amigaos-strip

TARGET  = smb2-handler
VERSION = 53

LIBSMB2DIR = libsmb2-git

OPTIMIZE = -O2
DEBUG    = -gstabs
INCLUDES = -I./$(LIBSMB2DIR)/include
WARNINGS = -Wall -Wwrite-strings -Werror

CFLAGS  = $(OPTIMIZE) $(DEBUG) $(INCLUDES) $(WARNINGS)
LDFLAGS = -static
LIBS    = 

STRIPFLAGS = -R.comment --strip-unneeded-rel-relocs

SRCS = 

OBJS = $(addprefix obj/,$(SRCS:.c=.o))

.PHONY: all
all: $(TARGET)

.PHONY: build-libsmb2
build-libsmb2:
	$(MAKE) -C $(LIBSMB2DIR) libsmb2.a

obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIBSMB2DIR)/libsmb2.a: build-libsmb2
	@true

$(TARGET): $(OBJS) $(LIBSMB2DIR)/libsmb2.a
	$(CC) $(LDFLAGS) -o $@.debug $^ $(LIBS)
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

.PHONY: clean
clean:
	$(MAKE) -C $(LIBSSH2DIR) clean
	rm -rf $(TARGET) $(TARGET).debug obj

.PHONY: revision
revision:
	bumprev -e si $(VERSION) $(TARGET)
