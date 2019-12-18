#!/bin/bash

set -e

case ${TESTTYPE} in
  UNIT)
    pytype . && pytest -l -s -n 2 -v --cov=tests/ --cov=networkml/ --cov-report term-missing -c .coveragerc && coverage
    ;;
  DOCKER)
    make test
    ;;
  *)
    echo TESTTYPE not set.
    exit 1
    ;;
esac
