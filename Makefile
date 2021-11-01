.PHONY: build upload_test

build:
	# 打包库
	@rm -rf dist/*
	@python3 -m build

upload_test:
	@python3 -m twine upload --config-file .pypirc --repository testpypi dist/*

upload:
	@python3 -m twine upload --config-file .pypirc --repository pypi dist/*
