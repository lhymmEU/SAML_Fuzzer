#!/bin/zsh

openssl req -x509 -newkey rsa -keyout key.pem -out cert.pem -sha1 -days 365
