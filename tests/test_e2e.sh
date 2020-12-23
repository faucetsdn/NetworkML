#!/bin/bash

set -e

TMPDIR=$(mktemp -d)
networkml ./tests/test_data/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap -o $TMPDIR --first_stage parser --final_stage algorithm --operation predict
LABEL=$(jq < $TMPDIR/predict.json '.data.mac_addresses["00:04:00:81:81:d0"]["classification"]["labels"][0]')
if [[ "$LABEL" == "" ]] ; then
    echo FAIL: no result from prediction
fi
TD=$(pwd)
docker build -f Dockerfile . -t iqtlabs/networkml:latest
docker run -i -e RESULT_PATH=/tmp/predict.json -v $TD/tests/test_data:/pcaps iqtlabs/networkml:latest /pcaps/trace_ab12_2001-01-01_02_03-client-ip-1-2-3-4.pcap -o/tmp
echo PASS
