#!/usr/bin/env python

"""bless_client

Usage:
  bless_client.py region lambda_function_name bastion_user bastion_user_ip remote_username bastion_source_ip bastion_command <id_rsa.pub to sign> <output id_rsa-cert.pub>

"""
import json
import sys

import boto3
import os

def main(argv):
    if len(argv) != 9:
        print (
            'Usage: bless_client.py region lambda_function_name bastion_user bastion_user_ip remote_username bastion_source_ip bastion_command <id_rsa.pub to sign> <output id_rsa-cert.pub>')
        return -1

    credentials_file = os.path.join(os.environ['HOME'], '.aws', 'credentials')
    if 'AWS_SECRET_ACCESS_KEY' not in os.environ and not os.path.isfile(credentials_file):
        print ('You need AWS credentials in your environment')
        return -1

    region = argv[0]

    with open(argv[7], 'r') as f:
        public_key = f.read()

    payload = {'bastion_user': argv[2], 'bastion_user_ip': argv[3], 'remote_username': argv[4],
               'bastion_ip': argv[5],
               'command': argv[6], 'public_key_to_sign': public_key}
    payload_json = json.dumps(payload)

    print('Executing:')
    lambda_client = boto3.client('lambda', region_name=region)
    response = lambda_client.invoke(FunctionName=argv[1], InvocationType='RequestResponse',
                                    LogType='None', Payload=payload_json)
    print('{}\n\n'.format(response['ResponseMetadata']))

    if response['StatusCode'] != 200:
        print ('Error creating cert.')
        return -1

    cert = response['Payload'].read()

    with open(argv[8], 'w') as cert_file:
        cert_file.write(cert[1:len(cert) - 3])


if __name__ == '__main__':
    main(sys.argv[1:])
