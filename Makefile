override CCFLAGS += -Iinc -Wall -Wextra -Wno-unused-function -fPIC

HOST ?= $(shell uname)
TARGET ?= $(shell uname)
LIBPREFIX ?= bin/$(TARGET)/lib

TARGET_CC := $(CROSS_COMPILE)$(CC)
TARGET_AR := $(CROSS_COMPILE)$(AR)

ifeq ($(TARGET),Windows)
	override LDFLAGS += -lws2_32
	LIBPREFIX ?= bin/Windows/
else
	ifeq ($(TARGET),Linux)
		override CCFLAGS += $(shell pkg-config --cflags liburing)
		override LDFLAGS += $(shell pkg-config --libs liburing)
	endif
endif

NAME ?= ev

SHARED := $(LIBPREFIX)$(NAME)
STATIC := $(LIBPREFIX)$(NAME).a
OBJECT := $(LIBPREFIX)$(NAME).o

ifeq ($(TARGET),Windows)
	SHARED := $(SHARED).dll
else
	SHARED := $(SHARED).so
endif

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

$(SHARED): $(OBJECT) | bin/$(TARGET)/
	$(TARGET_CC) $(CCFLAGS) -shared $^ -o $@ $(LDFLAGS)

%.a: %.o | bin/$(TARGET)/
	$(TARGET_AR) rcs $@ $^

$(LIBPREFIX)ev.o: src/ev.c | bin/$(TARGET)/
	$(TARGET_CC) $(CCFLAGS) -c $^ -o $@

%/:
	mkdir -p $@
