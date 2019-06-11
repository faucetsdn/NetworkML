FROM networkml
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENTRYPOINT ["pytest"]
CMD ["-l", "-s", "-v", "--cov=tests/", "--cov=networkml/", "--cov-report", "term-missing", "-c", ".coveragerc"]
