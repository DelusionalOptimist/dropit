#!/bin/env bash

mount -t debugfs none /sys/kernel/debug
apache2ctl start
INTERFACE_NAME=eth0 /app/dropit
