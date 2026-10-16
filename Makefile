CXX ?= g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -MMD -MP
LDFLAGS = 

TARGET = titan-packet-filter
SRC_DIR = src
BUILD_DIR = build
TEST_DIR = tests
BENCH_DIR = benchmark

SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))
DEPS = $(OBJS:.o=.d)

all: build

build: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(DEPS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

test:
	@if [ -d "$(TEST_DIR)" ] && [ "$$(((ls -1 $(TEST_DIR)/*.cpp $(TEST_DIR)/*.cc 2>/dev/null | wc -l)))" -gt 0 ]; then \
		echo "Running tests..."; \
		$(CXX) $(CXXFLAGS) $(TEST_DIR)/*.cpp -o $(BUILD_DIR)/test_runner $(LDFLAGS) && $(BUILD_DIR)/test_runner; \
	else \
		echo "No tests found in $(TEST_DIR). Skipping."; \
	fi

benchmark:
	@if [ -d "$(BENCH_DIR)" ] && [ "$$(((ls -1 $(BENCH_DIR)/*.cpp $(BENCH_DIR)/*.cc 2>/dev/null | wc -l)))" -gt 0 ]; then \
		echo "Running benchmarks..."; \
		$(CXX) $(CXXFLAGS) $(BENCH_DIR)/*.cpp -o $(BUILD_DIR)/bench_runner $(LDFLAGS) && $(BUILD_DIR)/bench_runner; \
	else \
		echo "No benchmarks found in $(BENCH_DIR). Skipping."; \
	fi

clean:
	@rm -rf $(BUILD_DIR)

.PHONY: all build test benchmark clean