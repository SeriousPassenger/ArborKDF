CXX ?= c++
PYTHON ?= python3

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

MAINTENANCE_GOALS := clean verify-wordlists regenerate-wordlists
ONLY_MAINTENANCE_GOALS := $(and $(MAKECMDGOALS),\
	$(if $(filter-out $(MAINTENANCE_GOALS),$(MAKECMDGOALS)),,1))

ifneq ($(TARGET_OS),linux)
ifneq ($(ONLY_MAINTENANCE_GOALS),1)
$(error ArborKDF randomness is not implemented yet for TARGET_OS '$(TARGET_OS)'; this version is Linux-only)
endif
endif

EXEEXT :=
NULL_DEVICE := /dev/null
CLI_TEST_ENV :=
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
PROGRAM_STEM := $(PROGRAM_STEM)-sanitize
TEST_STEM := $(TEST_STEM)-sanitize
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
LIB_SOURCES := \
	src/cli.cpp \
	src/codec.cpp \
	src/crypto.cpp \
	src/entropy.cpp \
	src/file.cpp \
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

.PHONY: all clean test check static sanitize verify-wordlists regenerate-wordlists

all: $(PROGRAM)

verify-wordlists:
	$(PYTHON) extras/gen_wordlist_header.py --check

regenerate-wordlists:
	$(PYTHON) extras/gen_wordlist_header.py

$(LIB_OBJECTS) $(PROGRAM_OBJECTS) $(TEST_OBJECTS): | verify-wordlists

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
	$(PYTHON) tests/test_wordlist_generator.py
	./$(PROGRAM) --help >$(NULL_DEVICE)
	./$(PROGRAM) subkey --help >$(NULL_DEVICE)
	./$(PROGRAM) masterkey --help >$(NULL_DEVICE)
	./$(PROGRAM) salt --help >$(NULL_DEVICE)
	./$(PROGRAM) encoding --help >$(NULL_DEVICE)
	./$(PROGRAM) wordlist --help >$(NULL_DEVICE)
	./$(PROGRAM) subkey generate --help >$(NULL_DEVICE)
	./$(PROGRAM) masterkey generate --help >$(NULL_DEVICE)
	./$(PROGRAM) salt generate --help >$(NULL_DEVICE)
	./$(PROGRAM) encoding encode --help >$(NULL_DEVICE)
	./$(PROGRAM) encoding decode --help >$(NULL_DEVICE)
	./$(PROGRAM) wordlist list --help >$(NULL_DEVICE)
	./$(PROGRAM) wordlist export --help >$(NULL_DEVICE)
	$(PYTHON) tests/test_wordlist_cli.py ./$(PROGRAM)
	$(PYTHON) tests/test_cli_recovery.py ./$(PROGRAM)
	@test "$$(./$(PROGRAM) encoding encode \
		--input-hex 0000000000000000000000 --wordlist embedded_bip39)" = \
		"abandon abandon abandon abandon abandon abandon abandon abandon"
	@test "$$(./$(PROGRAM) encoding encode \
		--input-hex 0000000000000000000000 \
		--wordlist ./third_party/bip39/english.txt)" = \
		"abandon abandon abandon abandon abandon abandon abandon abandon"
	@test "$$(./$(PROGRAM) encoding decode \
		--input-words 'abandon abandon abandon abandon abandon abandon abandon abandon' \
		--wordlist embedded_bip39)" = "0000000000000000000000"
	@test "$$(printf '%s\n' \
		'abandon ability able about above absent absorb abstract absurd abuse access accident' | \
		$(CLI_TEST_ENV) ./$(PROGRAM) subkey generate \
		--input-encoding wordlist --input-wordlist embedded_bip39 --master-stdin \
		--salt-hex 000102030405060708090a0b0c0d0e0f \
		--path /testing/path --pbkdf2-iterations 1 \
		--argon2-memory-kib 8 --argon2-iterations 1 --argon2-parallelism 1 \
		--security-target 128 --output-bits 264 --output-encoding wordlist \
		--output-wordlist embedded_bip39)" = \
		"faith recycle bullet shrug tortoise faith recall hospital save mixed super voice pattern satoshi refuse coin fall romance snake kitchen prize rule shift school"
	@test "$$(printf 'test\n' | $(CLI_TEST_ENV) ./$(PROGRAM) subkey generate \
		--input-encoding utf8 --master-stdin \
		--salt-hex 000102030405060708090a0b0c0d0e0f \
		--path /testing/path --pbkdf2-iterations 1 \
		--argon2-memory-kib 8 --argon2-iterations 1 --argon2-parallelism 1 \
		--security-target 128 --output-bits 256 --output-encoding hex)" = \
		"455489cba2bf8306a4ee11ba39260d7e2ba61d14474d7948f02e9e13eca4348c"

static:
	$(MAKE) STATIC=1 TARGET_OS=$(TARGET_OS) all

sanitize:
	$(MAKE) SANITIZE=1 TARGET_OS=$(TARGET_OS) check

clean:
	rm -rf -- build arborkdf arborkdf-tests arborkdf-static arborkdf-tests-static \
		arborkdf-sanitize arborkdf-tests-sanitize \
		arborkdf-static-sanitize arborkdf-tests-static-sanitize \
		arborkdf.exe arborkdf-tests.exe arborkdf-static.exe \
		arborkdf-tests-static.exe arborkdf-sanitize.exe \
		arborkdf-tests-sanitize.exe arborkdf-static-sanitize.exe \
		arborkdf-tests-static-sanitize.exe

-include $(DEPENDENCIES)
