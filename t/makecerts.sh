#!/bin/bash
mkdir -p private certs

for i in 01 02 03 04 ; do
	openssl genrsa -out private/$i-key.pem  1024
	openssl req -new -x509 -key private/$i-key.pem -subj "/CN=Dummy $i" -days 365 -set_serial $i -out certs/$i.pem
done
