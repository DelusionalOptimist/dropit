#!/bin/env bash

mount -t debugfs none /sys/kernel/debug
#apache2ctl start
/goserver 2>1 > /dev/null &
/dropit/dropit "$@"
