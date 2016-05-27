#!/bin/bash

[ -r ../shell_helper.sh ] || { echo "Cannot source shell_helper.sh"; exit -1; }
source ../shell_helper.sh

## send card ID not recognize
($INSTR send_card 40:a0:83:81
    sleep $SLEEP_TIME
    kill $(cat pid-file)
)&

#start leosac and wait for return value
(valgrind --error-exitcode=42 ./install/bin/leosac -k $TMP_DIR/this_test/test-test-card.xml > leosac-log &
    echo $! > pid-file;  wait $! && echo $? > exit-status)

## check test sequence was NOT run.
if grep "\[debug\]" $TMP_DIR/leosac-log | grep "Running test sequence..."; then
    fail "Test sequence was run";
fi

die 0
