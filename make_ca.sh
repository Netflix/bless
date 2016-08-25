#!/bin/bash
PASS=`openssl rand -base64 30`
ssh-keygen -t rsa -b 4096 -f bless-ca-key -N $PASS -C "SSH CA Key"

# IAD
ENCPASS=`aws kms encrypt --region us-east-1 --key-id 'arn:aws:kms:us-east-1:036177710368:key/0a66690a-63e4-4e8a-94f5-1412c90321ba' --plaintext $PASS --query CiphertextBlob`
echo "Your encrypted password (IAD): $ENCPASS"

#us-west-2
ENCPASS=`aws kms encrypt --region us-west-2 --key-id 'arn:aws:kms:us-west-2:036177710368:key/9c53e079-44b6-473e-a497-fa7f39f50016' --plaintext $PASS --query CiphertextBlob`
echo "Your encrypted password (us-west-2): $ENCPASS"
