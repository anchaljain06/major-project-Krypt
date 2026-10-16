# Minimal ProVerif image for the Krypt v1 models.
#
#   docker build -t krypt-proverif .
#   docker run --rm -v "$PWD":/work -w /work krypt-proverif proverif handshake.pv
#
# ProVerif comes from opam on top of the official ocaml/opam image.
# The version is pinned so the outputs in results/ are reproducible.
FROM ocaml/opam:debian-12-ocaml-4.14

ARG PROVERIF_VERSION=2.05

# Only the command-line tool is needed (no GTK interactive simulator).
RUN opam update -y \
 && opam install -y "proverif.${PROVERIF_VERSION}" \
 && opam clean -a -c -s --logs

# Put the binary on a fixed path so `docker run ... proverif` works without
# `eval $(opam env)`. The ocaml/opam images grant the opam user sudo.
RUN sudo ln -s "$(opam var bin)/proverif" /usr/local/bin/proverif \
 && proverif -help >/dev/null 2>&1 || true

WORKDIR /work
CMD ["proverif", "-help"]
