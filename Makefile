SHELL:=/bin/bash
PIP=$(shell which pip3 || echo "pip3")


# CONDA_EXE must be set before running `make dev` or `rmdev`
# export CONDA_EXE=$_CONDA_EXE
CONDA_DEV=netml-dev
CONDAROOT=$(shell ${CONDA_EXE} info --base)/bin
CONDA_ENV=$(shell ${CONDA_EXE} info --base)/envs/$(CONDA_DEV)/bin

run: predict
predict: build predict_nobuild
predict_nobuild:
	@echo
	@echo "Running Predict on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps$(PCAP)" networkml /pcaps
	@echo
train: build train_nobuild
train_nobuild:
	@echo
	@echo "Running Train on PCAP files $(PCAP)"
	@docker run -it --rm -v "$(PCAP):/pcaps$(PCAP)" -v "$(PWD)/networkml/trained_models:/usr/local/lib/python3.8/site-packages/networkml/trained_models/" networkml -O train /pcaps
	@echo
test: build
	@docker build -t networkml-test -f Dockerfile.test .
	@docker run --rm networkml-test
build:
	@docker build -t networkml .
install:
	pip3 install .

dev:
	${CONDA_EXE} env create --force -f $(CONDA_DEV).yml python=3.7
	source $(CONDAROOT)/activate $(CONDA_DEV) ; \
	$(CONDA_ENV)/pip install --upgrade pip ; \
	$(CONDA_ENV)/pip install .

rmdev:
	${CONDA_EXE} env remove -y -n $(CONDA_DEV)
