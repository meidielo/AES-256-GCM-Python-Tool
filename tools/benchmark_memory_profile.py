from __future__ import annotations

import gc
import json
import os
import sys
import tempfile
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secure_vault import SecureVault


def _measure_peak_bytes(work):
    gc.collect()
    tracemalloc.start()
    work()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak


def main() -> None:
    size = int(os.environ.get("SECURE_VAULT_BENCH_BYTES", str(2 * 1024 * 1024)))
    chunk_size = int(os.environ.get("SECURE_VAULT_BENCH_CHUNK_BYTES", str(64 * 1024)))
    passphrase = "benchmark-only-passphrase"
    vault = SecureVault()

    with tempfile.TemporaryDirectory() as temp_dir:
        input_path = os.path.join(temp_dir, "input.bin")
        stream_output_path = os.path.join(temp_dir, "stream.svstream")
        with open(input_path, "wb") as f:
            f.write(b"A" * size)

        def single_shot_encrypt() -> None:
            with open(input_path, "rb") as f:
                plaintext = f.read()
            vault.encrypt(plaintext, passphrase)

        def streaming_encrypt() -> None:
            with open(input_path, "rb") as source, open(stream_output_path, "wb") as destination:
                vault.encrypt_stream(source, destination, passphrase, chunk_size=chunk_size)

        result = {
            "input_bytes": size,
            "stream_chunk_bytes": chunk_size,
            "single_shot_peak_tracemalloc_bytes": _measure_peak_bytes(single_shot_encrypt),
            "stream_peak_tracemalloc_bytes": _measure_peak_bytes(streaming_encrypt),
            "note": "tracemalloc excludes native Argon2/OpenSSL allocations, so compare Python allocation shape only.",
        }
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
