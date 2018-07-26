![alt text](bless_logo.png "BLESS")
# BLESS - Bastion's Lambda Ephemeral SSH Service
[![Build Status](https://travis-ci.org/Netflix/bless.svg?branch=master)](https://travis-ci.org/Netflix/bless) [![Test coverage](https://coveralls.io/repos/github/Netflix/bless/badge.svg?branch=master)](https://coveralls.io/github/Netflix/bless) [![Join the chat at https://gitter.im/Netflix/bless](https://badges.gitter.im/Netflix/bless.svg)](https://gitter.im/Netflix/bless?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) [![NetflixOSS Lifecycle](https://img.shields.io/osslifecycle/Netflix/bless.svg)]()

BLESS is an SSH Certificate Authority that runs as an AWS Lambda function and is used to sign SSH
public keys.

SSH Certificates are an excellent way to authorize users to access a particular SSH host,
as they can be restricted for a single use case, and can be short lived.  Instead of managing the
authorized_keys of a host, or controlling who has access to SSH Private Keys, hosts just
need to be configured to trust an SSH CA.

BLESS should be run as an AWS Lambda in an isolated AWS account.  Because BLESS needs access to a
private key which is trusted by your hosts, an isolated AWS account helps restrict who can access
that private key, or modify the BLESS code you are running.

AWS Lambda functions can use an AWS IAM Policy to limit which IAM Roles can invoke the Lambda
Function.  If properly configured, you can restrict which IAM Roles can request SSH Certificates.
For example, your SSH Bastion (aka SSH Jump Host) can run with the only IAM Role with access to
invoke a BLESS Lambda Function configured with the SSH CA key trusted by the instances accessible
to that SSH Bastion.

## Getting Started
These instructions are to get BLESS up and running in your local development environment.
### Installation Instructions
Clone the repo:

    $ git clone git@github.com:Netflix/bless.git

Cd to the bless repo:

    $ cd bless

Create a virtualenv if you haven't already:

    $ python3.6 -m venv venv

Activate the venv:

    $ source venv/bin/activate

Install package and test dependencies:

    (venv) $ make develop

Run the tests:

    (venv) $ make test


## Deployment
To deploy an AWS Lambda Function, you need to provide a .zip with the code and all dependencies.
The .zip must contain your lambda code and configurations at the top level of the .zip.  The BLESS
Makefile includes a publish target to package up everything into a deploy-able .zip if they are in
the expected locations.

### Compiling BLESS Lambda Dependencies
AWS Lambda has some limitations, and to deploy code as a Lambda Function, you need to package up
all of the dependencies.  AWS Lambda only supports Python 2.7 and BLESS depends on
[Cryptography](https://cryptography.io/en/latest/), which must be compiled.  You will need to
compile and include your dependencies before you can publish a working AWS Lambda.

You can use a docker container running amazon linux:
- Execute ```make lambda-deps``` and this will run a container and save all the dependencies in ./aws_lambda_libs

Alternatively you can:
- Deploy an [Amazon Linux AMI](http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html)
- SSH onto that instance
- Copy BLESS' `setup.py` to the instance
- Copy BLESS' `bless/__about__.py` to the instance at `bless/__about__.py`
- Install BLESS' dependencies:
```
$ sudo yum install gcc libffi-devel openssl-devel
$ virtualenv venv
$ source venv/bin/activate
(venv) $ pip install --upgrade pip setuptools
(venv) $ pip install -e .
```
- From that instance, copy off the contents of:
```
$ cp -r venv/lib/python2.7/site-packages/. aws_lambda_libs
$ cp -r venv/lib64/python2.7/site-packages/. aws_lambda_libs
```
- put those files in: ./aws_lambda_libs/

### Protecting the CA Private Key
- Generate a password protected RSA Private Key:
```
$ ssh-keygen -t rsa -b 4096 -f bless-ca- -C "SSH CA Key"
```
- Use KMS to encrypt your password.  You will need a KMS key per region, and you will need to
encrypt your password for each region.  You can use the AWS Console to paste in a simple lambda
function like this:
```
import boto3
import base64
import os


def lambda_handler(event, context):
    region = os.environ['AWS_REGION']
    client = boto3.client('kms', region_name=region)
    response = client.encrypt(
    KeyId='alias/your_kms_key',
    Plaintext='Do not forget to delete the real plain text when done'
    )

    ciphertext = response['CiphertextBlob']
    return base64.b64encode(ciphertext)
```

- Manage your Private Keys .pem files and passwords outside of this repo.
- Update your bless_deploy.cfg with your Private Key's filename and encrypted passwords.
- Provide your desired ./lambda_configs/ca_key_name.pem prior to Publishing a new Lambda .zip
- Set the permissions of ./lambda_configs/ca_key_name.pem to 444.

You can now provide your private key and/or encrypted private key password via the lambda environment or config file.
In the `[Bless CA]` section, you can set `ca_private_key` instead of the `ca_private_key_file` with a base64 encoded
version of your .pem (e.g. `cat key.pem | base64` ).

Because every config file option is supported in the environment, you can also just set `bless_ca_default_password`
and/or `bless_ca_ca_private_key`.  Due to limits on AWS Lambda environment variables, you'll need to compress RSA 4096
private keys, which you can now do by setting `bless_ca_ca_private_key_compression`. For example, set 
`bless_ca_ca_private_key_compression = bz2` and `bless_ca_ca_private_key` to the output of 
`cat ca-key.pem | bzip2 | base64`.

### BLESS Config File
- Refer to the the [Example BLESS Config File](bless/config/bless_deploy_example.cfg) and its
included documentation.
- Manage your bless_deploy.cfg files outside of this repo.
- Provide your desired ./lambda_configs/bless_deploy.cfg prior to Publishing a new Lambda .zip
- The required [Bless CA] option values must be set for your environment.
- Every option can be changed in the environment. The environment variable name is contructed
as section_name_option_name (all lowercase, spaces replaced with underscores).

### Publish Lambda .zip
- Provide your desired ./lambda_configs/ca_key_name.pem prior to Publishing
- Provide your desired [BLESS Config File](bless/config/bless_deploy_example.cfg) at
./lambda_configs/bless_deploy.cfg prior to Publishing
- Provide the [compiled dependencies](#compiling-bless-lambda-dependencies) at ./aws_lambda_libs
- run:
```
(venv) $ make publish
```

- deploy ./publish/bless_lambda.zip to AWS via the AWS Console,
[AWS SDK](http://boto3.readthedocs.io/en/latest/reference/services/lambda.html), or
[S3](https://aws.amazon.com/blogs/compute/new-deployment-options-for-aws-lambda/)
- remember to deploy it to all regions.


### Lambda Requirements
You should deploy this function into its own AWS account to limit who has access to modify the
code, configs, or IAM Policies.  An isolated account also limits who has access to the KMS keys
used to protect the SSH CA Key.

The BLESS Lambda function should run as its own IAM Role and will need access to an AWS KMS Key in
each region where the function is deployed.  The BLESS IAMRole will also need permissions to obtain
random from kms (kms:GenerateRandom) and permissions for logging to CloudWatch Logs
(logs:CreateLogGroup,logs:CreateLogStream,logs:PutLogEvents).

## Using BLESS
After you have [deployed BLESS](#deployment) you can run the sample [BLESS Client](bless_client/bless_client.py)
from a system with access to the required [AWS Credentials](http://boto3.readthedocs.io/en/latest/guide/configuration.html).

    (venv) $ ./bless_client.py region lambda_function_name bastion_user bastion_user_ip remote_usernames bastion_source_ip bastion_command <id_rsa.pub to sign> <output id_rsa-cert.pub>


## Verifying Certificates
You can inspect the contents of a certificate with ssh-keygen directly:

    $ ssh-keygen -L -f your-cert.pub

## Enabling BLESS Certificates On Servers
Add the following line to /etc/ssh/sshd_config:

    TrustedUserCAKeys /etc/ssh/cas.pub

Add a new file, owned by and only writable by root, at /etc/ssh/cas.pub with the contents:

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQ…  #id_rsa.pub of an SSH CA
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQ…  #id_rsa.pub of an offline SSH CA
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQ…  #id_rsa.pub of an offline SSH CA 2

To simplify SSH CA Key rotation you should provision multiple CA Keys, and leave them offline until
you are ready to rotate them.

Additional information about the TrustedUserCAKeys file is [here](https://www.freebsd.org/cgi/man.cgi?sshd_config(5))

## Project resources
- Source code <https://github.com/netflix/bless>
- Issue tracker <https://github.com/netflix/bless/issues>
