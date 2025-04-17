CXX := g++
CXXFLAGS := -std=c++17 -Os

LIBC_TYPE := $(shell ldd --version 2>&1 | grep -q musl && echo musl || echo glibc)

ifeq ($(LIBC_TYPE),glibc)
    CXXFLAGS += -flto=thin
endif

bupt-net-login: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^
	strip bupt-net-login

cc: main.cpp
	docker run --rm -v $(shell pwd):/workdir -e CROSS_TRIPLE=$(ARCH) multiarch/crossbuild make
	mv bupt-net-login bupt-net-login_$(ARCH)

run: bupt-net-login
	./bupt-net-login -d

.PHONY: run