PYTHON ?= python

.PHONY: seed eval test lint

seed:
	$(PYTHON) -m backend.training.train_classifier

eval:
	$(PYTHON) -m backend.eval.benchmark
	$(PYTHON) -m backend.eval.suite --phase advanced

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check backend
	$(PYTHON) -m black --check backend
