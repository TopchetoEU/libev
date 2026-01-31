override CCFLAGS += -Iinc -Wall -Wextra -fPIC

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

	override CCFLAGS_DYN += $(shell pkg-config --cflags libffi)
	override LDFLAGS_DYN += $(shell pkg-config --libs libffi)
endif

NAME ?= ev

SHARED := $(LIBPREFIX)$(NAME)
STATIC := $(LIBPREFIX)$(NAME).a
OBJECT := $(LIBPREFIX)$(NAME).o

SHARED_DYN := $(LIBPREFIX)$(NAME)-dyn
STATIC_DYN := $(LIBPREFIX)$(NAME)-dyn.a
OBJECT_DYN := $(LIBPREFIX)$(NAME)-dyn.o

ifeq ($(TARGET),Windows)
	SHARED := $(SHARED).dll
	SHARED_DYN := $(SHARED_DYN).dll
else
	SHARED := $(SHARED).so
	SHARED_DYN := $(SHARED_DYN).so
endif

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

$(SHARED): $(OBJECT) | bin/$(TARGET)/
	$(TARGET_CC) $(CCFLAGS) -shared $^ -o $@ $(LDFLAGS)

$(SHARED_DYN): $(OBJECT_DYN) | bin/$(TARGET)/
	$(TARGET_CC) $(CCFLAGS) $(CCFLAGS_DYN) -shared $^ -o $@ $(LDFLAGS) $(LDFLAGS_DYN)

%.a: %.o | bin/$(TARGET)/
	$(TARGET_AR) rcs $@ $^

$(LIBPREFIX)ev.o: src/ev.c | bin/$(TARGET)/
	$(TARGET_CC) $(CCFLAGS) -c $^ -o $@

$(LIBPREFIX)ev-dyn.o: src/ev-dyn.c | bin/$(TARGET)/
	$(TARGET_CC) $(CCFLAGS) $(CCFLAGS_DYN) -c $^ -o $@

%/:
	mkdir -p $@
