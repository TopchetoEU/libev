override CCFLAGS += -Iinc
override CCFLAGS += -Wall
override CCFLAGS += -fPIC

$(info $())

override LDFLAGS += $(shell pkg-config --libs liburing)
override CCFLAGS += $(shell pkg-config --cflags liburing)

SRCS += src/ev.c

NAME ?= ev

SHARED := bin/lib$(NAME).so
STATIC := bin/lib$(NAME).a
OBJECT := bin/lib$(NAME).o

ifeq ($(DEBUG),yes)
	override CCFLAGS += -g
endif

.PHONY: sources flags all clean

all: $(SHARED) $(STATIC)
clean:
	rm -rf bin

sources:
	echo $(SRCS)
flags:
	echo $(CCFLAGS)

$(SHARED): $(OBJECT)
	mkdir -p bin
	$(CC) $(CCFLAGS) $(LDFLAGS) -shared $^ -o $@

$(STATIC): $(OBJECT)
	mkdir -p bin
	$(AR) rcs $@ $^

$(OBJECT): $(SRCS)
	mkdir -p bin
	$(CC) $(CCFLAGS) -c $^ -o $@
