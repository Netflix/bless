#!/usr/bin/env python

"""bless_client

Usage:
  bless_client.py region lambda_function_name bastion_user bastion_user_ip remote_username bastion_ip bastion_command <id_rsa.pub to sign> <output id_rsa-cert.pub>

    region: AWS region where your lambda is deployed

    lambda_function_name: The AWS Lambda function's alias or ARN to invoke

    bastion_user: The user on the bastion, who is initiating the SSH request.

    bastion_user_ip: The IP of the user accessing the bastion.

    remote_username: The username on the remote server that will be used in the SSH
    request.  This is enforced in the issued certificate.

    bastion_ip: The source IP where the SSH connection will be initiated from.  This is
    enforced in the issued certificate.

    bastion_command: Text information about the SSH request of the bastion_user.

    id_rsa.pub to sign: The id_rsa.pub that will be used in the SSH request.  This is
    enforced in the issued certificate.

    output id_rsa-cert.pub: The file where the certificate should be saved.  Per man SSH(1):
        "ssh will also try to load certificate information from the filename
        obtained by appending -cert.pub to identity filenames" e.g.  the <id_rsa.pub to sign>
"""
import base64
import json
import stat
import sys

import boto3
import os


def main(argv):
    if len(argv) != 9:
        print (
            'Usage: bless_client.py region lambda_function_name bastion_user bastion_user_ip remote_username bastion_ip bastion_command <id_rsa.pub to sign> <output id_rsa-cert.pub>')
        return -1

    region = argv[0]
    lambda_function_name = argv[1]
    bastion_user = argv[2]
    bastion_user_ip = argv[3]
    remote_username = argv[4]
    bastion_ip = argv[5]
    bastion_command = argv[6]
    public_key_filename = argv[7]
    certificate_filename = argv[8]

    with open(public_key_filename, 'r') as f:
        public_key = f.read()

    payload = {'bastion_user': bastion_user, 'bastion_user_ip': bastion_user_ip,
               'remote_username': remote_username, 'bastion_ip': bastion_ip,
               'command': bastion_command, 'public_key_to_sign': public_key}
    payload_json = json.dumps(payload)

    print('Executing:')
    lambda_client = boto3.client('lambda', region_name=region)
    response = lambda_client.invoke(FunctionName=lambda_function_name,
                                    InvocationType='RequestResponse', LogType='None',
                                    Payload=payload_json)
    print('{}\n'.format(response['ResponseMetadata']))

    if response['StatusCode'] != 200:
        print ('Error creating cert.')
        return -1

    cert = response['Payload'].read()

    flags = os.O_WRONLY | os.O_CREAT
    with os.fdopen(os.open(certificate_filename, flags, 0o600), 'w') as cert_file:
        cert_file.write(cert[1:len(cert) - 3])

    # If cert_file already existed with the incorrect permissions, fix them.
    file_status = os.stat(certificate_filename)
    if 0o600 != (file_status.st_mode & 0o777):
        os.chmod(certificate_filename, stat.S_IRUSR | stat.S_IWUSR)

    print('Wrote Certificate to: ' + certificate_filename)


if __name__ == '__main__':
    main(sys.argv[1:])
