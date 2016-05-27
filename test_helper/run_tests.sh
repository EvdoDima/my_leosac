#!/bin/bash
#
# Run shell script based tests
#

RCol='\e[0m' # Text Reset
Bla='\e[0;30m';
Red='\e[0;31m';
Gre='\e[0;32m';
Yel='\e[0;33m';
Blu='\e[0;34m';

if [ "$1" = "serial" ]
then
    ## Run test serialy, one by one.
    for f in `find . -name "test-*" -maxdepth 1 -mindepth 1 -type d`
    do
        ./run_docker.sh $f || { echo -e ${Red} "Error in test $f" ${RCol} ; exit -1 ; }
    done    
fi

which parallel > /dev/null || { echo "Need GNU parallel." ; exit 1; }

echo "Running tests, using $1 as install directory"
echo "New tests suite: `date`" > RES

total_test=`find . -maxdepth 1 -mindepth 1 -type d | wc -l`
echo -e ${Yel} "We will run ${total_test} tests" ${RCol}

## the run_docker script require a test-folder name.
find . -name "test-*" -maxdepth 1 -mindepth 1 -type d | parallel ./run_docker.sh {} ;

RET_VALUE=$?
## parallel ret value is our test suite return value.
if [ ${RET_VALUE} -eq 0 ] ; then
    echo -e ${Gre}"All tests succeded"${RCol}
else
    echo -e ${Red} "Some failure... ret value = ${RET_VALUE}"${RCol}
fi

exit 0
