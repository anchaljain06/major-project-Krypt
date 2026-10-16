# Krypt v1 ProVerif models.
#
#   make check          build the image (if needed), run every model,
#                       save full output to results/<model>.txt and the
#                       RESULT lines of all models to results/summary.txt
#   make results/X.txt  run one model
#   make image          (re)build the Docker image only
#
# ProVerif runs in Docker (see Dockerfile). Set PROVERIF=proverif to use a
# local install instead:  make check PROVERIF=proverif DOCKER_RUN=

IMAGE      ?= krypt-proverif
PROVERIF   ?= proverif
TIMEOUT    ?= 3600
DOCKER_RUN ?= docker run --rm -v "$(CURDIR)":/work -w /work $(IMAGE)

MODELS := handshake handshake_nocache handshake_samelabel ratchet \
          binding_weak binding_fixed binding_weak_unauth binding_fixed_unauth

RESULTS := $(MODELS:%=results/%.txt)

.PHONY: check image summary clean FORCE

check: image $(RESULTS) summary

image:
	@if [ -n "$(DOCKER_RUN)" ]; then \
	  docker image inspect $(IMAGE) >/dev/null 2>&1 || docker build -t $(IMAGE) . ; \
	fi

# Each run records the ProVerif version, the full output and the wall time.
results/%.txt: %.pv FORCE
	@mkdir -p results
	@echo "== $<"
	@$(DOCKER_RUN) sh -c '\
	  { echo "# $(PROVERIF) $< ($$($(PROVERIF) -help 2>&1 | head -1))"; \
	    s=$$(date +%s%N); \
	    timeout $(TIMEOUT) $(PROVERIF) $< 2>&1; rc=$$?; \
	    e=$$(date +%s%N); \
	    echo "# exit=$$rc wall_ms=$$(( (e - s) / 1000000 ))"; } > $@'
	@grep -E '^RESULT|^# exit' $@ || true

summary:
	@for m in $(MODELS); do \
	  echo "== $$m"; grep -E '^RESULT|^# exit' results/$$m.txt; \
	done > results/summary.txt
	@cat results/summary.txt

clean:
	rm -rf results

FORCE:
