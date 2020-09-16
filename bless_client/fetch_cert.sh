#!/bin/bash
set -e

if [[ $# -lt 2 || $# -gt 2 ]] 
then
    echo "Usage: 
    ./fetch_cert.sh username <id_rsa.pub to sign>"
    exit        
fi
user_ip=`dig +short myip.opendns.com @resolver1.opendns.com`
public_key=`cat $2`
cat <<EOT > payload.json
{
    "region": "us-east-1",
    "lambda_function_name": "bless",
    "bastion_user": "$1",
    "bastion_user_ip": "$user_ip",
    "remote_usernames": "ubuntu",
    "bastion_ips": "$user_ip",
    "bastion_command": "Welcome to Bless",
    "public_key": "$public_key"
}

EOT

echo "invoking aws bless client-lambda"

aws lambda invoke --invocation-type RequestResponse --function-name bless_client --region us-east-1 --log-type Tail --payload file://./payload.json --cli-binary-format raw-in-base64-out id_rsa-cert.pub
