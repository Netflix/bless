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
    if len(argv) < 9 or len(argv) > 10:
        print (
            'Usage: bless_client.py region lambda_function_name bastion_user bastion_user_ip remote_username bastion_source_ip bastion_command <id_rsa.pub to sign> <output id_rsa-cert.pub> [kmsauth token]')
        return -1

    region = argv[0]

    with open(argv[7], 'r') as f:
        public_key = f.read()

    payload = {'bastion_user': argv[2], 'bastion_user_ip': argv[3], 'remote_username': argv[4],
               'bastion_ips': argv[5],
               'command': argv[6], 'public_key_to_sign': public_key}

    if len(argv) == 10:
        payload['kmsauth_token'] = argv[9]

    payload_json = json.dumps(payload)

    print('Executing:')
    print('payload_json is: \'{}\''.format(payload_json))
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
