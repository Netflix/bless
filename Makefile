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
	coverage run --branch --source=bless -m py.test tests
	coverage html

publish:
	mkdir -p ./publish/bless_lambda
	cp -r ./bless ./publish/bless_lambda/
	mv ./publish/bless_lambda/bless/aws_lambda/* ./publish/bless_lambda/
	cp -r ./aws_lambda_libs/* ./publish/bless_lambda/
	cp -r ./lambda_configs/* ./publish/bless_lambda/
	cd ./publish/bless_lambda && zip -r ../bless_lambda.zip .

.PHONY: develop dev-docs clean test lint coverage publish
