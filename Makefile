test: lint
	@echo "--> Running Python tests"
	py.test tests || exit 1
	@echo ""

develop:
	@echo "--> Installing dependencies"
	pip install -r requirements.txt
	pip install "file://`pwd`#egg=bless[tests]"
	@echo ""

dev-docs:
	# todo the docs, so typical, right?

clean:
	@echo "--> Cleaning pyc files"
	find . -name "*.pyc" -delete
	rm -rf ./publish ./htmlcov
	@echo ""

lint:
	@echo "--> Linting Python files"
	PYFLAKES_NODOCTEST=1 flake8 bless
	@echo ""

coverage:
	@echo "--> Running Python tests with coverage"
	coverage run --branch --source=bless -m py.test tests || exit 1
	coverage html
	@echo ""

publish:
	rm -rf ./publish/bless_lambda/
	mkdir -p ./publish/bless_lambda
	cp -r ./bless ./publish/bless_lambda/
	mv ./publish/bless_lambda/bless/aws_lambda/* ./publish/bless_lambda/
	cp -r ./aws_lambda_libs/. ./publish/bless_lambda/
	if [ -d ./lambda_configs/ ]; then cp -r ./lambda_configs/. ./publish/bless_lambda/; fi
	cd ./publish/bless_lambda && zip -FSr ../bless_lambda.zip .

compile:
	yum install -y gcc libffi-devel openssl-devel python36 python36-virtualenv
	virtualenv-3.6 /tmp/venv
	/tmp/venv/bin/pip install --upgrade pip setuptools
	/tmp/venv/bin/pip install -e .
	cp -r /tmp/venv/lib/python3.6/site-packages/. ./aws_lambda_libs
	cp -r /tmp/venv/lib64/python3.6/site-packages/. ./aws_lambda_libs

lambda-deps:
	@echo "--> Compiling lambda dependencies"
	docker run --rm -it -v ${CURDIR}:/src -w /src amazonlinux:1 make compile

.PHONY: develop dev-docs clean test lint coverage publish
