MACHINE := $(shell uname -m)
ARCH := $(patsubst aarch64,arm64,$(MACHINE))
ARCH := $(patsubst x86_64,amd64,$(ARCH))
HOSTNAME ?= $(shell hostname)
PERF := $(ARCH)/${HOSTNAME}

reflect:
	go build

old.txt: | reflect
	mkdir -p $(PERF)
	go test -v -count=1 | tee $(PERF)/old.txt

new.txt: | reflect
	mkdir -p $(PERF)
	go test -v -count=1 | tee $(PERF)/new.txt

.PHONY: stat
stat: $(PERF)/old.txt $(PERF)/new.txt
	@echo "This benchmark shows the difference in performance against the baseline."
	@echo "The results may vary if the machine was under (heavy) load."
	@echo
	@echo "~~~"
	@uptime | sed 's/^ //'
	@echo
	@cat $(PERF)/new.txt
	@echo "~~~"
	@echo
	@echo "~~~"
	@benchstat $(PERF)/old.txt $(PERF)/new.txt
	@echo "~~~"

.PHONY: clean
clean:
	rm $(PERF)/new.txt
