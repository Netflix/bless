#!/bin/sh

yum install -y python37
python3.7 -m venv /tmp/venv
/tmp/venv/bin/pip install --upgrade pip setuptools
/tmp/venv/bin/pip install -e .
cp -r /tmp/venv/lib/python3.7/site-packages/. ./aws_lambda_libs
cp -r /tmp/venv/lib64/python3.7/site-packages/. ./aws_lambda_libs
