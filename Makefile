MVN := mvn

.PHONY: help compile run run-sudo clean package test

help:
	@printf "Targets:\\n"
	@printf "  make compile  - Compile the project\\n"
	@printf "  make run      - Run the desktop application\\n"
	@printf "  make run-sudo - Run the desktop application with sudo\\n"
	@printf "  make dist     - Build the fat jar distribution\\n"
	@printf "  make package  - Build the jar/package\\n"
	@printf "  make test     - Run tests\\n"
	@printf "  make clean    - Remove build output\\n"

compile:
	$(MVN) compile

run:
	$(MVN) exec:java

run-sudo:
	sudo -E $(MVN) exec:java

dist:
	$(MVN) -DskipTests package

package:
	$(MVN) package

test:
	$(MVN) test

clean:
	$(MVN) clean
