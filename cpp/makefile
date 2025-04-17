CXXFLAGS := -std=c++17 -Os
STRIP := strip

ifdef TOOLCHAIN 
CXX := $(TOOLCHAIN)-g++
STRIP := $(TOOLCHAIN)-strip
endif

bupt-net-login: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^
	$(STRIP) bupt-net-login || true

run: bupt-net-login
	./bupt-net-login -d

.PHONY: run