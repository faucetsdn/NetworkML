SHELL:=/bin/bash
PIP=$(shell which pip3 || echo "pip3")


# CONDA_EXE must be set before running `make dev` or `rmdev`
# export CONDA_EXE=$_CONDA_EXE
CONDA_DEV=posml-dev
CONDAROOT=$(shell ${CONDA_EXE} info --base)/bin
CONDA_ENV=$(shell ${CONDA_EXE} info --base)/envs/$(CONDA_DEV)/bin

run: eval_onelayer
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
	@echo "DEV/STANDALONE OPTIONS:"
	@echo "dev                                     Uses conda to create a contained python development environment"
	@echo "rmdev                                   Removes the conda development environment"
eval_onelayer: build run_redis eval_onelayer_nobuild
eval_onelayer_nobuild:
	@echo
	@echo "Running OneLayer Eval on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/" --link poseidonml-redis:redis -e POSEIDON_PUBLIC_SESSIONS=1 -e LOG_LEVEL=$(LOG_LEVEL) poseidonml
	@docker rm -f poseidonml-redis > /dev/null
	@echo
test_onelayer: build run_redis test_onelayer_nobuild
test_onelayer_nobuild:
	@echo
	@echo "Running OneLayer Test on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/" -v "$(PWD)/networkml/trained_models:/poseidonml/networkml/trained_models" --link poseidonml-redis:redis -e POSEIDON_PUBLIC_SESSIONS=1 -e LOG_LEVEL=$(LOG_LEVEL) poseidonml -o test -w networkml/trained_models/onelayer/test_onelayer.json
	@docker rm -f poseidonml-redis > /dev/null
	@echo
train_onelayer: build run_redis train_onelayer_nobuild
train_onelayer_nobuild:
	@echo
	@echo "Running OneLayer Train on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/" -v "$(PWD)/networkml/trained_models:/poseidonml/networkml/trained_models" --link poseidonml-redis:redis -e POSEIDON_PUBLIC_SESSIONS=1 -e LOG_LEVEL=$(LOG_LEVEL) poseidonml -o train
	@docker rm -f poseidonml-redis > /dev/null
	@echo
eval_randomforest: build run_redis eval_randomforest_nobuild
eval_randomforest_nobuild:
	@echo
	@echo "Running RandomForest Eval on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/" --link poseidonml-redis:redis -e POSEIDON_PUBLIC_SESSIONS=1 -e LOG_LEVEL=$(LOG_LEVEL) poseidonml -a randomforest -m networkml/trained_models/randomforest/RandomForestModel.pkl -w networkml/trained_models/randomforest/RandomForestModel.pkl
	@docker rm -f poseidonml-redis > /dev/null
	@echo
test_randomforest: build run_redis test_randomforest_nobuild
test_randomforest_nobuild:
	@echo
	@echo "Running RandomForest Test on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/" --link poseidonml-redis:redis -e POSEIDON_PUBLIC_SESSIONS=1 -e LOG_LEVEL=$(LOG_LEVEL) poseidonml -o test -a randomforest -m networkml/trained_models/randomforest/RandomForestModel.pkl -w networkml/trained_models/randomforest/RandomForestModel.pkl
	@docker rm -f poseidonml-redis > /dev/null
	@echo
train_randomforest: build run_redis train_randomforest_nobuild
train_randomforest_nobuild:
	@echo
	@echo "Running RandomForest Train on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/" -v "$(PWD)/networkml/trained_models:/poseidonml/networkml/trained_models" --link poseidonml-redis:redis -e POSEIDON_PUBLIC_SESSIONS=1 -e LOG_LEVEL=$(LOG_LEVEL) poseidonml -o train -a randomforest -m networkml/trained_models/randomforest/RandomForestModel.pkl -w networkml/trained_models/randomforest/RandomForestModel.pkl
	@docker rm -f poseidonml-redis > /dev/null
	@echo
eval_sos: build run_redis eval_sos_nobuild
eval_sos_nobuild:
	@echo
	@echo "Running SoSModel Eval on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/" --link poseidonml-redis:redis -e POSEIDON_PUBLIC_SESSIONS=1 -e LOG_LEVEL=$(LOG_LEVEL) poseidonml -a sos
	@docker rm -f poseidonml-redis > /dev/null
	@echo
train_sos: build run_redis train_sos_nobuild
train_sos_nobuild:
	@echo
	@echo "Running SoSModel Train on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps/" -v "$(PWD)/networkml/trained_models:/poseidonml/networkml/trained_models" --link poseidonml-redis:redis -e POSEIDON_PUBLIC_SESSIONS=1 -e LOG_LEVEL=$(LOG_LEVEL) poseidonml -o train -a sos -m networkml/trained_models/sos/SoSmodel -w networkml/trained_models/sos/SoSmodel.pkl
	@docker rm -f poseidonml-redis > /dev/null
	@echo
run_redis:
	@docker run -d --name poseidonml-redis redis:latest
test:
	docker build -t poseidonml-test -f Dockerfile.test .
	docker run -it --rm poseidonml-test
build: clean
	@docker build -t poseidonml .
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
