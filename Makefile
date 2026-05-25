.PHONY: install test cov lint clean build

install:
	python -m pip install -e ".[test]"

test:
	pytest -xvs

cov:
	pytest --cov=provenex_verifier --cov-report=term-missing --cov-report=html

clean:
	rm -rf build dist *.egg-info .coverage htmlcov .pytest_cache

build:
	python -m pip install --upgrade build
	python -m build
