# Copyright (c) 2021,  NVIDIA CORPORATION
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SHELL := /bin/bash

VERSION := 0.1.0
DATE := $(shell date +"%Y-%m-%d")
ARCH := $(shell go version | awk '{print $$4}' | tr '/' '-')

LDFLAGS=-ldflags "-w -X main.releaseDate=$(DATE) -X main.versionNumber=$(VERSION)"

linux:
	go fmt
	GOOS=linux GOARCH=amd64 go build -o fluxtunnel $(LDFLAGS) main.go

darwin:
	go fmt
	GOOS=darwin GOARCH=amd64 go build -o fluxtunnel $(LDFLAGS) main.go

release-linux:
	mkdir -p bin/test
	tar zcvf bin/test/fluxtunnel-$(VERSION)-linux-amd64.tgz fluxtunnel

release-darwin:
	mkdir -p bin/test
	tar zcvf bin/test/fluxtunnel-$(VERSION)-darwin-amd64.tgz fluxtunnel

tests:

clean:
	rm ./fluxtunnel
