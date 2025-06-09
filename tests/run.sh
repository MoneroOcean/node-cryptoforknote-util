#!/bin/bash -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR
node arq.js  || exit 1
node bloc.js || exit 1
node ird.js  || exit 1
node msr.js  || exit 1
node ryo.js  || exit 1
node sal.js  || exit 1
node tube.js || exit 1
node xeq.js  || exit 1
node xhv.js  || exit 1
node xla.js  || exit 1
node xmr.js  || exit 1
node xmv.js  || exit 1
node xtnc.js || exit 1
node zeph.js || exit 1
