override CCFLAGS += -Iinc
override CCFLAGS += -Wall
override CCFLAGS += -Wextra
override CCFLAGS += -fPIC

$(info $())

override LDFLAGS += $(shell pkg-config --libs liburing)
override CCFLAGS += $(shell pkg-config --cflags liburing)

NAME ?= ev

SHARED := bin/lib$(NAME).so
STATIC := bin/lib$(NAME).a
OBJECT := bin/lib$(NAME).o

SHARED_DYN := bin/lib$(NAME)-dyn.so
STATIC_DYN := bin/lib$(NAME)-dyn.a
OBJECT_DYN := bin/lib$(NAME)-dyn.o

ifeq ($(DEBUG),yes)
	override CCFLAGS += -g
endif

.PHONY: sources flags all clean

all: $(SHARED) $(STATIC) $(SHARED_DYN) $(STATIC_DYN)
clean:
	rm -rf bin

sources:
	echo $(SRCS)
flags:
	echo $(CCFLAGS)

$(SHARED): $(OBJECT) | bin/
	$(CC) $(CCFLAGS) $(LDFLAGS) -shared $^ -o $@

$(SHARED_DYN): $(OBJECT_DYN) | bin/
	$(CC) $(CCFLAGS) $(LDFLAGS) -lffi -shared $^ -o $@

%.a: %.o | bin/
	$(AR) rcs $@ $^

$(OBJECT): src/ev.c | bin/
	$(CC) $(CCFLAGS) -c $^ -o $@

$(OBJECT_DYN): src/ev-dyn.c | bin/
	$(CC) $(CCFLAGS) -c $^ -o $@

bin/:
	mkdir -p bin
