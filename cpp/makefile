bupt-net-login: main.cpp
	g++ -std=c++17 -flto=thin -Os -o bupt-net-login main.cpp
	strip bupt-net-login

cc: main.cpp
	docker run --rm -v $(shell pwd):/workdir -e CROSS_TRIPLE=$(ARCH) multiarch/crossbuild make
	mv bupt-net-login bupt-net-login_$(ARCH)

run: bupt-net-login
	./bupt-net-login -d

.PHONY: run