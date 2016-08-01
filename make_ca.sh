#!/bin/bash

PASS=`openssl rand -base64 30`
ssh-keygen -t rsa -b 4096 -f bless-ca-key -N $PASS -C "SSH CA Key"
echo -n "Enter your your key-id: "
read KEYID
ENCPASS=`aws kms encrypt --key-id $KEYID --plaintext $PASS --query CiphertextBlob`
echo "Your encrypted password: $ENCPASS"
