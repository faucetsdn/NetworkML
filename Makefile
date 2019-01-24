SHELL:=/bin/bash
PIP=$(shell which pip3 || echo "pip3")


# CONDA_EXE must be set before running `make dev` or `rmdev`
# export CONDA_EXE=$_CONDA_EXE
CONDA_DEV=testABC
CONDAROOT=$(shell ${CONDA_EXE} info --base)/bin
CONDA_ENV=$(shell ${CONDA_EXE} info --base)/envs/$(CONDA_DEV)/bin

run: build_onelayer eval_onelayer
help:
	@echo "make OPTION      (see below for description; requires setting PCAP environment variable)"
	@echo
	@echo Set the PCAP environment variable to the directory of pcaps or a single pcap file you want to work with
	@echo
	@echo "eval_[onelayer|randomforest|sosmodel]   Runs a directory of pcap files against specified model"
	@echo "test_[onelayer|randomforest]            Tests directory of pcaps against specified model"
	@echo "train_[onelayer|randomforest|sosmodel]  Trains directory of pcaps against specified model"
	@echo "install                                 Installs the python library"
	@echo "run                                     Equivalent to eval_onelayer"
	@echo
	@echo "dev                                     Uses conda to create a contained python development environment"
	@echo "rmdev                                   Removes the conda development environment"
eval_onelayer: build_onelayer run_redis eval_onelayer_nobuild
eval_onelayer_nobuild:
	@echo
	@echo "Running OneLayer Eval on PCAP file $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcap/$(PCAP)" --link poseidonml-redis:redis -e SKIP_RABBIT=true -e POSEIDON_PUBLIC_SESSIONS=1 -e LOG_LEVEL=$(LOG_LEVEL) --entrypoint=python3 poseidonml:onelayer eval_OneLayer.py /pcap/$(PCAP)
	@docker rm -f poseidonml-redis > /dev/null
	@echo
test_onelayer: build_onelayer run_redis test_onelayer_nobuild
test_onelayer_nobuild:
	@echo
	@echo "Running OneLayer Test on PCAP files $(PCAP)"
	@docker run -it --rm -v "/tmp/models:/OneLayer/models" -v "$(PCAP):/pcaps/" --link poseidonml-redis:redis -e SKIP_RABBIT=true -e LOG_LEVEL=$(LOG_LEVEL) --entrypoint=python3 poseidonml:onelayer train_OneLayer.py
	@docker rm -f poseidonml-redis > /dev/null
	@echo
train_onelayer: build_onelayer run_redis train_onelayer_nobuild
train_onelayer_nobuild:
	@echo
	@echo "Running OneLayer Train on PCAP files $(PCAP)"
	@docker run -it --rm -v "/tmp/models:/OneLayer/models" -v "$(PCAP):/pcaps/" --link poseidonml-redis:redis -e SKIP_RABBIT=true -e LOG_LEVEL=$(LOG_LEVEL) --entrypoint=python3 poseidonml:onelayer train_OneLayer.py
	@docker rm -f poseidonml-redis > /dev/null
	@echo
eval_randomforest: build_randomforest run_redis eval_randomforest_nobuild
eval_randomforest_nobuild:
	@echo
	@echo "Running RandomForest Eval on PCAP file $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/$(PCAP)" --link poseidonml-redis:redis -e SKIP_RABBIT=true -e LOG_LEVEL=$(LOG_LEVEL) --entrypoint=python3 poseidonml:randomforest eval_RandomForest.py /pcaps/$(PCAP)
	@docker rm -f poseidonml-redis > /dev/null
	@echo
test_randomforest: build_randomforest run_redis test_randomforest_nobuild
test_randomforest_nobuild:
	@echo
	@echo "Running RandomForest Test on PCAP files $(PCAP)"
	@docker run -it --rm -v "/tmp/models:/RandomForest/models" -v "$(PCAP):/pcaps/" --link poseidonml-redis:redis -e SKIP_RABBIT=true -e LOG_LEVEL=$(LOG_LEVEL) --entrypoint=python3 poseidonml:randomforest test_RandomForest.py
	@docker rm -f poseidonml-redis > /dev/null
	@echo
train_randomforest: build_randomforest run_redis train_randomforest_nobuild
train_randomforest_nobuild:
	@echo
	@echo "Running RandomForest Train on PCAP files $(PCAP)"
	@docker run -it --rm -v "/tmp/models:/RandomForest/models" -v "$(PCAP):/pcaps/" --link poseidonml-redis:redis -e SKIP_RABBIT=true -e LOG_LEVEL=$(LOG_LEVEL) --entrypoint=python3 poseidonml:randomforest train_RandomForest.py
	@docker rm -f poseidonml-redis > /dev/null
	@echo
eval_sosmodel: build_sosmodel run_redis eval_sosmodel_nobuild
eval_sosmodel_nobuild:
	@echo
	@echo "Running SoSModel Eval on PCAP file $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/$(PCAP)" --link poseidonml-redis:redis -e SKIP_RABBIT=true -e LOG_LEVEL=$(LOG_LEVEL) --entrypoint=python3 poseidonml:sosmodel eval_SoSModel.py /pcaps/$(PCAP)
	@docker rm -f poseidonml-redis > /dev/null
	@echo
train_sosmodel: build_sosmodel run_redis train_sosmodel_nobuild
train_sosmodel_nobuild:
	@echo
	@echo "Running SoSModel Train on PCAP files $(PCAP)"
	@docker run -it --rm -v "/tmp/models:/new_models" --link poseidonml-redis:redis -v "$(PCAP):/pcaps/" -e SKIP_RABBIT=true -e LOG_LEVEL=$(LOG_LEVEL) --entrypoint=python3 poseidonml:sosmodel train_SoSModel.py /pcaps/ /models/SoSModel.pkl
	@docker rm -f poseidonml-redis > /dev/null
	@echo
run_redis:
	@docker run -d --name poseidonml-redis redis:latest
build_onelayer: build_base
	@pushd DeviceClassifier/OneLayer && docker build -t poseidonml:onelayer . && popd
build_randomforest: build_base
	@pushd DeviceClassifier/RandomForest && docker build -t poseidonml:randomforest . && popd
build_sosmodel: build_base
	@cp -R DeviceClassifier/OneLayer/opts utils/
	@cp DeviceClassifier/OneLayer/models/OneLayerModel.pkl utils/models/
	@pushd utils && docker build -f Dockerfile.sosmodel -t poseidonml:sosmodel . && popd
	@rm -rf utils/opts
	@rm -rf utils/models/OneLayerModel.pkl
test: build_base
	docker build -t poseidonml-test -f Dockerfile.test .
	docker run -it --rm poseidonml-test
build_base: clean
	@docker build -t cyberreboot/poseidonml:base -f Dockerfile.base .
clean:
	docker rm -f poseidonml-redis || true
install:
	$(PIP) install -r requirements.txt
	python3 setup.py install

dev:
	${CONDA_EXE} env create --force -f $(CONDA_DEV).yml python=3.6
	source $(CONDAROOT)/activate $(CONDA_DEV) ;	\
	$(CONDA_ENV)/pip install --upgrade pip ;	\
	$(CONDA_ENV)/pip install .
rmdev:
	${CONDA_EXE} env remove -y -n $(CONDA_DEV)
