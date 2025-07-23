CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -I./include -O2
CXXFLAGS = -Wall -Wextra -std=c++11 -I../clam-master/crab/include -I../clam-master/include -O2 -Wno-parentheses
LDFLAGS = -ljson-c
LDFLAGS_CPP = -ljson-c -lrt 

SRC_DIR = tests
BUILD_DIR = ./tests/build
RUST_JSON = ./tests/build/rust_test_cases.json
C_JSON = ./tests/build/c_test_results.json
CPP_JSON = ./tests/build/cpp_test_results.json
CLAM_BUILD_DIR = ../clam-master/build
CLAM_LIB = $(CLAM_BUILD_DIR)/lib/libcrab.a

N ?= 100
ITERATIONS ?= 100

# 创建构建目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 编译tnum.c
$(BUILD_DIR)/tnum.o: $(SRC_DIR)/tnum.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/tnum_mul: $(SRC_DIR)/tnum_mul.c $(BUILD_DIR)/tnum.o | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 编译 clam-master 库
$(CLAM_LIB):
	mkdir -p $(CLAM_BUILD_DIR)
	cd $(CLAM_BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=/usr/lib/llvm-14/lib/cmake/llvm -DCRAB_BUILD_TESTS=OFF ..
	cd $(CLAM_BUILD_DIR) && make crab

# 编译 verify_cpp.cpp，并链接 clam-master 库
$(BUILD_DIR)/verify_cpp: $(SRC_DIR)/verify_cpp.cpp $(CLAM_LIB) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(CLAM_LIB) $(LDFLAGS_CPP)

# 生成测试用例（运行test.rs）
$(RUST_JSON): | $(BUILD_DIR)
	cargo run --release --bin test_mul -- $(ITERATIONS) $(N)

# 执行完整测试流程
test: build rust-test cpp-test compare-results

build: $(BUILD_DIR)

# 运行Rust测试
rust-test: $(RUST_JSON)
	@echo "Rust test completed, generated test cases: $(RUST_JSON)"

# 运行C++实现测试 (作为基准)
cpp-test: $(BUILD_DIR)/verify_cpp rust-test
	$(BUILD_DIR)/verify_cpp $(RUST_JSON) $(ITERATIONS)
	@echo "C++ tnum test completed, generated results: $(CPP_JSON)"

# 比较结果
compare-results: cpp-test
	@echo "Comparing test results..."
	cargo run --release --bin compare -- $(CPP_JSON)
	@echo "Test comparison completed"

# 清理
clean:
	rm -rf $(BUILD_DIR) $(RUST_JSON) $(C_JSON) $(CPP_JSON) $(CLAM_BUILD_DIR)
	cargo clean

# 显示帮助
help:
	@echo "Usage:"
	@echo "  make test [N=100] [ITERATIONS=100]      - Execute the full test flow (Rust -> C++ -> Compare)"
	@echo "  make rust-test [N=100] [ITERATIONS=100] - Only run Rust tests to generate cases"
	@echo "  make cpp-test [ITERATIONS=100]          - Run C++ baseline tests"
	@echo "  make clean                              - Clean all generated files"

.PHONY: test rust-test c-test cpp-test compare-results clean help build-clam