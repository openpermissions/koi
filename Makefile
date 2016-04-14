# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

.PHONY: clean requirements test pylint html docs

# You should not set these variables from the command line.
# Directory that this Makfile is in
SERVICEDIR        = $(shell pwd)

# Directory containing the source code
SOURCE_DIR        = koi

# Directory to output the test reports
TEST_REPORTS_DIR  = tests/unit/reports

# You can set these variables from the command line.
# App to build docs from python sphinx commented code
SPHINXAPIDOC      = sphinx-apidoc

# Directory to build docs in
BUILDDIR          = $(SERVICEDIR)/_build

# Service version (required for $(SPHINXAPIDOC))
SERVICE_VERSION   = 0.4.5

# Service release (required for $(SPHINXAPIDOC))
SERVICE_RELEASE   = 0.4.5

# Directory to output python in source sphinx documentation
IN_SOURCE_DOC_DIR = $(BUILDDIR)/in_source

# Directory to output markdown converted docs to
SERVICE_DOC_DIR   = $(BUILDDIR)/service/html

# Directory to find markdown docs
DOC_DIR           = $(SERVICEDIR)/documents

# Directory to find markdown docs
SPHINX_DIR           = $(SERVICEDIR)/docs

# Create list of target .html file names to be created based on all .md files found in the 'doc directory'
md_docs :=  $(patsubst $(DOC_DIR)/%.md,$(SERVICE_DOC_DIR)/%.html,$(wildcard $(DOC_DIR)/*.md)) \
                $(SERVICE_DOC_DIR)/README.html

clean:
	rm -fr $(TEST_REPORTS_DIR)

# Install requirements
requirements:
	pip install -r $(SERVICEDIR)/requirements.txt

# Run tests
test:
	mkdir -p $(TEST_REPORTS_DIR)
	py.test \
		-s \
		--cov $(SOURCE_DIR) tests \
		--cov-report html \
		--cov-report xml \
		--junitxml=$(TEST_REPORTS_DIR)/unit-tests-report.xml
	cloverpy $(TEST_REPORTS_DIR)/coverage.xml > $(TEST_REPORTS_DIR)/clover.xml

# Run pylint
pylint:
	mkdir -p $(TEST_REPORTS_DIR)
	@pylint $(SOURCE_DIR)/ --output-format=html > $(TEST_REPORTS_DIR)/pylint-report.html || {\
	 	echo "\npylint found some problems."\
		echo "Please refer to the report: $(TEST_REPORTS_DIR)/pylint-report.html\n";\
	 }

# Create .html docs from source code comments in python sphinx format
sphinx:
	$(SPHINXAPIDOC) \
		-s rst \
		--full \
		-V $(SERVICE_VERSION) \
		-R $(SERVICE_RELEASE) \
		-H $(SOURCE_DIR) \
		-A "Open Permissions Platform Coalition" \
		-o $(SPHINX_DIR) $(SOURCE_DIR)


html: sphinx
	cd $(SPHINX_DIR) && PYTHONPATH=$(SERVICEDIR) make html BUILDDIR=$(IN_SOURCE_DOC_DIR)



# Dependencies of .html document files created from files in the 'doc directory'
$(SERVICE_DOC_DIR)/%.html : $(DOC_DIR)/%.md
	mkdir -p $(dir $@)
	grip $< --export $@

# Dependenciy of .html document files created from README.md
$(SERVICE_DOC_DIR)/%.html : $(SERVICEDIR)/%.md
	mkdir -p $(dir $@)
	grip $< --export $@

# Create .html docs from all markdown files
md_docs: $(md_docs)
ifneq ($(wildcard $(DOC_DIR)),)
# Copy dependent files required to render the views, e.g. images
	rsync \
		--exclude '*.md' \
		--exclude 'eap' \
		--exclude 'drawio' \
		-r \
		$(DOC_DIR)/ $(SERVICE_DOC_DIR)
endif

# Create all docs
docs: html md_docs
