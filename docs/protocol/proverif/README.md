# Krypt v1 in ProVerif

Symbolic models of the Krypt v1 handshake (Krypt-X3K) and of the alternating KEM ratchet, written against `Krypt_Major_Project_Strategy.md` sections 4.3, 4.4, 4.7 and 4.8, and plan Phase 2 track P (steps 2.1-2.5).

```
make check        # builds the Docker image once, runs every model, writes results/
```

`results/<model>.txt` holds the full ProVerif output of the last run, with the exit code and wall time on its last line. `results/summary.txt` collects every `RESULT` line.

RESULTS_PLACEHOLDER
