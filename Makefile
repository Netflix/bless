test: lint
	@echo "--> Running Python tests"
	py.test tests || exit 1
	@echo ""

develop:
	@echo "--> Installing dependencies"
	pip3 install --upgrade pip setuptools
	pip3 install -r requirements.txt
	pip3 install "file://`pwd`#egg=bless[tests]"
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
	cp ./publish/bless_lambda/bless/aws_lambda/bless* ./publish/bless_lambda/
	cp -r ./aws_lambda_libs/. ./publish/bless_lambda/
	if [ -d ./lambda_configs/ ]; then cp -r ./lambda_configs/. ./publish/bless_lambda/; fi
	cd ./publish/bless_lambda && zip -FSr ../bless_lambda.zip .

compile:
	./lambda_compile.sh

lambda-deps:
	@echo "--> Compiling lambda dependencies"
	docker run --rm -v ${CURDIR}:/src -w /src amazonlinux:2 ./lambda_compile.sh

.PHONY: develop dev-docs clean test lint coverage publish
