CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
CPPFLAGS += -Iinclude -Isrc
LDLIBS += -lcrypto
BUILD_DIR := build
LIB_SOURCES := src/point.cpp src/crypto.cpp

.PHONY: all test clean
all: $(BUILD_DIR)/ecc_demo

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/ecc_demo: $(LIB_SOURCES) src/main.cpp src/openssl_size.hpp include/ecc/point.hpp include/ecc/crypto.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LIB_SOURCES) src/main.cpp -o $@ $(LDLIBS)

$(BUILD_DIR)/self_test: $(LIB_SOURCES) src/openssl_size.hpp tests/self_test.cpp include/ecc/point.hpp include/ecc/crypto.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LIB_SOURCES) tests/self_test.cpp -o $@ $(LDLIBS)

test: $(BUILD_DIR)/self_test
	./$(BUILD_DIR)/self_test

clean:
	rm -rf $(BUILD_DIR)
