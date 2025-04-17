CXXFLAGS := -std=c++17 -Os

bupt-net-login: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^
	$(CROSS_TRIPLE)-strip bupt-net-login

cc: main.cpp
	docker run --rm -v $(shell pwd):/workdir -e CROSS_TRIPLE=$(ARCH) multiarch/crossbuild make
	mv bupt-net-login bupt-net-login_$(ARCH)

run: bupt-net-login
	./bupt-net-login -d

.PHONY: run