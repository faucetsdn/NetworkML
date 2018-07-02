SHELL:=/bin/bash

run: build_onelayer eval_onelayer
eval_onelayer: build_onelayer
	@echo "Running OneLayer Eval on PCAP files in $(shell pwd)"
	@docker run -it -v "$(shell pwd):/pcaps" poseidonml:onelayer
test_onelayer: build_onelayer
	@echo "Running OneLayer Test on PCAP files in $(shell pwd)"
	@docker run -it -v "$(shell pwd):/pcaps" poseidonml:onelayer test_OneLayer.py
train_onelayer: build_onelayer
	@echo "Running OneLayer Train on PCAP files in $(shell pwd)"
	@docker run -it -v "$(shell pwd):/pcaps" poseidonml:onelayer train_OneLayer.py
eval_randomforest: build_randomforest
	@echo "Running RandomForest Eval on PCAP files in $(shell pwd)"
	@docker run -it -v "$(shell pwd):/pcaps" poseidonml:randomforest
test_randomforest: build_randomforest
	@echo "Running RandomForest Test on PCAP files in $(shell pwd)"
	@docker run -it -v "$(shell pwd):/pcaps" poseidonml:randomforest test_RandomForest.py
train_randomforest: build_randomforest
	@echo "Running RandomForest Train on PCAP files in $(shell pwd)"
	@docker run -it -v "$(shell pwd):/pcaps" poseidonml:randomforest train_RandomForest.py
build_onelayer: build_base
	@pushd DeviceClassifier/OneLayer && docker build -t poseidonml:onelayer . && popd
build_randomforest: build_base
	@pushd DeviceClassifier/RandomForest && docker build -t poseidonml:randomforest . && popd
build_base:
	@docker build -t poseidonml:base -f Dockerfile.base .
install:
	python3 setup.py install
