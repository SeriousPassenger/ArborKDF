CXX ?= c++

UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
ifeq ($(OS),Windows_NT)
TARGET_OS ?= windows
else ifeq ($(UNAME_S),Linux)
TARGET_OS ?= linux
else ifeq ($(UNAME_S),Darwin)
TARGET_OS ?= darwin
else
TARGET_OS ?= unknown
endif

ifeq ($(filter $(TARGET_OS),linux darwin windows),)
$(error unsupported TARGET_OS '$(TARGET_OS)'; use linux, darwin, or windows)
endif

EXEEXT :=
NULL_DEVICE := /dev/null
ifeq ($(TARGET_OS),windows)
EXEEXT := .exe
NULL_DEVICE := NUL
endif

BUILD_MODE := dynamic
PROGRAM_STEM := arborkdf
TEST_STEM := arborkdf-tests
OPTFLAGS := -O2
ifeq ($(STATIC),1)
BUILD_MODE := static
PROGRAM_STEM := arborkdf-static
TEST_STEM := arborkdf-tests-static
ARBORKDF_LDFLAGS += -static
endif
ifeq ($(SANITIZE),1)
BUILD_MODE := $(BUILD_MODE)-sanitize
OPTFLAGS := -O1
ARBORKDF_CXXFLAGS += -g -fno-omit-frame-pointer -fsanitize=address,undefined
ARBORKDF_LDFLAGS += -fsanitize=address,undefined
endif

PROGRAM := $(PROGRAM_STEM)$(EXEEXT)
TEST_PROGRAM := $(TEST_STEM)$(EXEEXT)
BUILD_DIR := build/$(TARGET_OS)-$(BUILD_MODE)

ARBORKDF_CPPFLAGS += -Iinclude -Ithird_party/argon2
ARBORKDF_CXXFLAGS += -std=c++17 $(OPTFLAGS) -Wall -Wextra -Wpedantic -Wconversion \
	-Wsign-conversion -Wshadow -Wformat=2 -Wnull-dereference -Wdouble-promotion \
	-Werror -MMD -MP

OPENSSL_LIBS ?= -lcrypto
ARGON2_LIBS ?= -largon2
ZLIB_LIBS ?= -lz
ARBORKDF_LDLIBS += $(OPENSSL_LIBS) $(ARGON2_LIBS) $(ZLIB_LIBS)

ifeq ($(TARGET_OS),linux)
ARBORKDF_LDLIBS += -pthread -ldl
endif
ifeq ($(TARGET_OS),darwin)
ARBORKDF_LDLIBS += -pthread
endif
ifeq ($(TARGET_OS),windows)
ARBORKDF_LDLIBS += -luser32
endif

LIB_SOURCES := \
	src/cli.cpp \
	src/codec.cpp \
	src/crypto.cpp \
	src/entropy.cpp \
	src/openssl_context.cpp \
	src/platform.cpp \
	src/wordlist.cpp
PROGRAM_SOURCES := src/main.cpp
TEST_SOURCES := \
	tests/test_main.cpp \
	tests/test_codec.cpp \
	tests/test_crypto.cpp \
	tests/test_entropy.cpp

LIB_OBJECTS := $(LIB_SOURCES:%.cpp=$(BUILD_DIR)/%.o)
PROGRAM_OBJECTS := $(PROGRAM_SOURCES:%.cpp=$(BUILD_DIR)/%.o)
TEST_OBJECTS := $(TEST_SOURCES:%.cpp=$(BUILD_DIR)/%.o)
DEPENDENCIES := $(LIB_OBJECTS:.o=.d) $(PROGRAM_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)

.PHONY: all clean test check static sanitize

all: $(PROGRAM)

$(PROGRAM): $(LIB_OBJECTS) $(PROGRAM_OBJECTS)
	$(CXX) $(LDFLAGS) $(ARBORKDF_LDFLAGS) -o $@ $^ $(LDLIBS) $(ARBORKDF_LDLIBS)

$(TEST_PROGRAM): $(LIB_OBJECTS) $(TEST_OBJECTS)
	$(CXX) $(LDFLAGS) $(ARBORKDF_LDFLAGS) -o $@ $^ $(LDLIBS) $(ARBORKDF_LDLIBS)

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(ARBORKDF_CPPFLAGS) $(CXXFLAGS) $(ARBORKDF_CXXFLAGS) -c $< -o $@

test: $(TEST_PROGRAM)
	./$(TEST_PROGRAM)

check: test $(PROGRAM)
	./$(PROGRAM) --help >$(NULL_DEVICE)
	./$(PROGRAM) subkey --help >$(NULL_DEVICE)
	./$(PROGRAM) masterkey --help >$(NULL_DEVICE)
	./$(PROGRAM) salt --help >$(NULL_DEVICE)
	./$(PROGRAM) encoding --help >$(NULL_DEVICE)
	./$(PROGRAM) subkey generate --help >$(NULL_DEVICE)
	./$(PROGRAM) masterkey generate --help >$(NULL_DEVICE)
	./$(PROGRAM) salt generate --help >$(NULL_DEVICE)
	./$(PROGRAM) encoding encode --help >$(NULL_DEVICE)
	./$(PROGRAM) encoding decode --help >$(NULL_DEVICE)
	@test "$$(printf 'test\n' | ./$(PROGRAM) subkey generate \
		--input-encoding utf8 --master-stdin \
		--salt-hex 000102030405060708090a0b0c0d0e0f \
		--path /testing/path --pbkdf2-iterations 1 \
		--argon2-memory-kib 8 --argon2-iterations 1 --argon2-parallelism 1 \
		--security-target 128 --output-bits 256 --output-encoding hex)" = \
		"455489cba2bf8306a4ee11ba39260d7e2ba61d14474d7948f02e9e13eca4348c"

static:
	$(MAKE) STATIC=1 TARGET_OS=$(TARGET_OS) all

sanitize:
	$(MAKE) SANITIZE=1 TARGET_OS=$(TARGET_OS) test

clean:
	rm -rf -- build arborkdf arborkdf-tests arborkdf-static arborkdf-tests-static \
		arborkdf.exe arborkdf-tests.exe arborkdf-static.exe arborkdf-tests-static.exe

-include $(DEPENDENCIES)
