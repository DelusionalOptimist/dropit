#!/bin/env bash

mount -t debugfs none /sys/kernel/debug
/app/dropit eth0
