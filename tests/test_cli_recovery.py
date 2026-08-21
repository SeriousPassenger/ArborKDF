#!/usr/bin/env python3
"""Recovery-format and strict-decoder integration tests for the ArborKDF CLI."""

from __future__ import annotations

import base64
import os
import subprocess
import sys


def invoke(
    program: str,
    arguments: list[str],
    *,
    stdin_line: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["MSYS2_ARG_CONV_EXCL"] = "*"
    environment["MSYS_NO_PATHCONV"] = "1"
    input_bytes = None if stdin_line is None else (stdin_line + "\n").encode("utf-8")
    try:
        return subprocess.run(
            [program, *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
            timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"command timed out: {arguments!r}") from error


def require_success(result: subprocess.CompletedProcess[bytes], description: str) -> str:
    if result.returncode != 0:
        raise RuntimeError(
            f"{description} failed ({result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace')}"
        )
    if (
        not result.stdout.endswith(b"\n")
        or b"\n" in result.stdout[:-1]
        or b"\r" in result.stdout
    ):
        raise RuntimeError(
            f"{description} did not emit exactly one canonical output line: "
            f"{result.stdout!r}"
        )
    try:
        return result.stdout[:-1].decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{description} emitted invalid UTF-8") from error


def require_failure(
    result: subprocess.CompletedProcess[bytes],
    message_part: str,
    description: str,
) -> None:
    stderr = result.stderr.decode("utf-8", errors="replace")
    if result.returncode == 0 or message_part not in stderr or result.stdout:
        raise RuntimeError(
            f"{description} did not fail with {message_part!r}; "
            f"status={result.returncode}, stdout={result.stdout!r}, "
            f"stderr={stderr!r}"
        )


def subkey_arguments(master_encoding: str, salt_arguments: list[str]) -> list[str]:
    return [
        "subkey",
        "generate",
        "--input-encoding",
        master_encoding,
        "--master-stdin",
        *salt_arguments,
        "--path",
        "/recovery/test",
        "--pbkdf2-iterations",
        "1",
        "--argon2-memory-kib",
        "8",
        "--argon2-iterations",
        "1",
        "--argon2-parallelism",
        "1",
        "--security-target",
        "128",
        "--output-bits",
        "256",
        "--output-encoding",
        "hex",
    ]


def derive(
    program: str,
    master_encoding: str,
    master_text: str,
    salt_arguments: list[str],
) -> str:
    return require_success(
        invoke(
            program,
            subkey_arguments(master_encoding, salt_arguments),
            stdin_line=master_text,
        ),
        f"{master_encoding} master derivation",
    )


def main() -> int:
    if len(sys.argv) != 2:
        raise RuntimeError("usage: test_cli_recovery.py PROGRAM")
    program = sys.argv[1]

    version = require_success(invoke(program, ["--version"]), "version query")
    expected_version = (
        "ArborKDF experimental-pre-release; derivation-suite=draft-v1; "
        "random-conditioner=ArborKDF/random-conditioner/v2; "
        "mouse-transcript=ArborKDF/mouse-transcript/v1"
    )
    if version != expected_version:
        raise RuntimeError(f"unexpected deterministic version string: {version!r}")

    # These are the exact transport operations used by byte-oriented generators.
    # Decoding either printed representation must recover the same raw master.
    generated_master = bytes(range(32))
    master_hex = generated_master.hex()
    master_base64 = base64.b64encode(generated_master).decode("ascii")
    generated_salt = bytes(range(22))  # 176 bits: compatible with BIP39's 11-bit indices.
    salt_hex = generated_salt.hex()
    salt_base64 = base64.b64encode(generated_salt).decode("ascii")
    hex_salt_arguments = ["--salt", salt_hex, "--salt-encoding", "hex"]

    # Independently computed from the byte-level draft-v1 specification using
    # Python's hashlib PBKDF2, cryptography Argon2id, and PyCryptodome KMAC256.
    # Pinning the result catches a shared CLI transport/framing regression.
    expected = "7521ea4412ee9905aa648f725ea51f8a00311d5cacf0dad97ee35029edbcb170"
    actual = derive(program, "hex", master_hex, hex_salt_arguments)
    if actual != expected:
        raise RuntimeError(
            f"raw-master known-answer mismatch: expected {expected}, got {actual}"
        )
    if derive(program, "base64", master_base64, hex_salt_arguments) != actual:
        raise RuntimeError("hex and Base64 transports did not recover the same raw master")
    if derive(program, "utf8", master_hex, hex_salt_arguments) == actual:
        raise RuntimeError("raw-byte and UTF-8 master domains unexpectedly collide")

    if derive(
        program,
        "hex",
        master_hex,
        ["--salt", salt_base64, "--salt-encoding", "base64"],
    ) != actual:
        raise RuntimeError("Base64 salt transport did not recover the generated salt")
    if derive(program, "hex", master_hex, ["--salt-hex", salt_hex]) != actual:
        raise RuntimeError("legacy --salt-hex changed salt semantics")

    salt_words = require_success(
        invoke(
            program,
            [
                "encoding",
                "encode",
                "--input-hex",
                salt_hex,
                "--wordlist",
                "embedded_bip39",
            ],
        ),
        "wordlist salt producer",
    )
    if derive(
        program,
        "hex",
        master_hex,
        [
            "--salt",
            salt_words,
            "--salt-encoding",
            "wordlist",
            "--salt-wordlist",
            "embedded_bip39",
        ],
    ) != actual:
        raise RuntimeError("wordlist salt transport did not recover the generated salt")

    require_failure(
        invoke(
            program,
            subkey_arguments(
                "hex",
                [
                    "--salt",
                    " ".join(["abandon"] * 745),
                    "--salt-encoding",
                    "wordlist",
                    "--salt-wordlist",
                    "embedded_bip39",
                ],
            ),
            stdin_line=master_hex,
        ),
        "8192-bit decoded-size limit",
        "oversized wordlist salt",
    )

    # Raw-master and salt boundaries are part of the recovery format contract.
    derive(program, "hex", "00", hex_salt_arguments)
    derive(program, "hex", "00" * 4096, hex_salt_arguments)
    require_failure(
        invoke(
            program,
            subkey_arguments("hex", hex_salt_arguments),
            stdin_line="",
        ),
        "must not be empty",
        "empty raw master",
    )
    require_failure(
        invoke(
            program,
            subkey_arguments("hex", hex_salt_arguments),
            stdin_line="00" * 4097,
        ),
        "byte limit",
        "oversized raw master",
    )

    derive(
        program,
        "hex",
        master_hex,
        ["--salt", "00" * 16, "--salt-encoding", "hex"],
    )
    derive(
        program,
        "hex",
        master_hex,
        ["--salt", "00" * 1024, "--salt-encoding", "hex"],
    )
    require_failure(
        invoke(
            program,
            subkey_arguments(
                "hex", ["--salt", "00" * 1025, "--salt-encoding", "hex"]
            ),
            stdin_line=master_hex,
        ),
        "maximum is 2048",
        "oversized salt",
    )

    for malformed, message in [
        ("Zg", "multiple of 4"),
        ("Zg= ", "padding"),
        ("Zh==", "tail bits"),
        ("Zm9=", "tail bits"),
    ]:
        require_failure(
            invoke(
                program,
                subkey_arguments("base64", hex_salt_arguments),
                stdin_line=malformed,
            ),
            message,
            f"malformed Base64 master {malformed!r}",
        )

    for malformed, message in [
        ("Zg", "multiple of 4"),
        ("Zg= ", "padding"),
        ("Zh==", "tail bits"),
        ("Zm9=", "tail bits"),
    ]:
        require_failure(
            invoke(
                program,
                subkey_arguments(
                    "hex", ["--salt", malformed, "--salt-encoding", "base64"]
                ),
                stdin_line=master_hex,
            ),
            message,
            f"malformed Base64 salt {malformed!r}",
        )

    require_failure(
        invoke(
            program,
            subkey_arguments("hex", ["--salt", "00" * 15, "--salt-encoding", "hex"]),
            stdin_line=master_hex,
        ),
        "between 16 and 1024 decoded bytes",
        "undersized salt",
    )
    require_failure(
        invoke(
            program,
            subkey_arguments(
                "hex",
                [
                    "--salt",
                    salt_hex,
                    "--salt-encoding",
                    "hex",
                    "--salt-hex",
                    salt_hex,
                ],
            ),
            stdin_line=master_hex,
        ),
        "cannot be combined",
        "ambiguous legacy and modern salt options",
    )
    require_failure(
        invoke(
            program,
            subkey_arguments(
                "hex",
                [
                    "--salt",
                    salt_hex,
                    "--salt-encoding",
                    "hex",
                    "--salt-wordlist",
                    "embedded_bip39",
                ],
            ),
            stdin_line=master_hex,
        ),
        "only valid with wordlist salt input",
        "wordlist selector with hex salt",
    )
    require_failure(
        invoke(
            program,
            subkey_arguments(
                "hex", ["--salt", salt_words, "--salt-encoding", "wordlist"]
            ),
            stdin_line=master_hex,
        ),
        "required for wordlist salt input",
        "missing wordlist salt selector",
    )

    profile_result = invoke(
        program,
        [
            "subkey",
            "generate",
            "--input-encoding",
            "hex",
            "--master-stdin",
            "--salt-hex",
            salt_hex,
            "--path",
            "/recovery/test",
            "--pbkdf2-iterations",
            "1",
            "--argon2-memory-kib",
            "65536",
            "--argon2-iterations",
            "3",
            "--argon2-parallelism",
            "5",
            "--security-target",
            "128",
            "--output-bits",
            "256",
            "--output-encoding",
            "hex",
        ],
        stdin_line=master_hex,
    )
    require_success(profile_result, "non-profile Argon2 tuple derivation")
    if b"not exactly either named RFC 9106 profile" not in profile_result.stderr:
        raise RuntimeError("p=5 incorrectly suppressed the RFC 9106 profile advisory")

    print("CLI recovery tests passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
