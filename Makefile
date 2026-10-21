.DEFAULT_GOAL := ci
.PHONY: ci build test validate vet format lint vuln tidy clean

# The same rootless Podman checks run locally and on the own-fork PR runner.
ci build test validate vet format lint vuln tidy:
	bash .github/scripts/fork-check.sh $@

clean:
	@echo 'Each check removes only its own ephemeral container, image and cache.'
