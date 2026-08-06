from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path


JAR_NAME = "survival-project-server-0.1.0-local.jar"
IRIS_MYSQL_USER_KEY = "IRIS_MYSQL_USER"
IRIS_MYSQL_PASSWORD_KEY = "IRIS_MYSQL_PASSWORD"  # pragma: allowlist secret
LOCAL_MACHINE_PROVIDER = "windows-dpapi-local-machine"
MAX_STORE_BYTES = 1_048_576


class SurvivalProjectLaunchError(RuntimeError):
    pass


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def decrypt_local_machine_dpapi(value: str) -> str:
    if os.name != "nt":
        raise SurvivalProjectLaunchError("The scoped Iris SQL Vault requires Windows DPAPI")
    try:
        encrypted = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise SurvivalProjectLaunchError("The scoped Iris SQL Vault contains invalid DPAPI data") from exc
    input_buffer = ctypes.create_string_buffer(encrypted)
    input_blob = DataBlob(len(encrypted), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_char)))
    output_blob = DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(input_blob), None, None, None, None, 0x01, ctypes.byref(output_blob)
    ):
        raise SurvivalProjectLaunchError("The scoped Iris SQL credential could not be decrypted")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(output_blob.pbData)


def load_iris_database_credentials(path: Path) -> dict[str, str]:
    try:
        if path.stat().st_size > MAX_STORE_BYTES:
            raise SurvivalProjectLaunchError("The scoped Iris SQL Vault exceeds its safety limit")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except SurvivalProjectLaunchError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SurvivalProjectLaunchError("The scoped Iris SQL Vault is unavailable or malformed") from exc
    expected = {IRIS_MYSQL_USER_KEY, IRIS_MYSQL_PASSWORD_KEY}
    encrypted = payload.get("credentials") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("version") != 1
        or payload.get("provider") != LOCAL_MACHINE_PROVIDER
        or not isinstance(encrypted, dict)
        or set(encrypted) != expected
    ):
        raise SurvivalProjectLaunchError("The scoped Vault must contain only the machine-protected Iris SQL identity")
    credentials = {
        "username": decrypt_local_machine_dpapi(str(encrypted[IRIS_MYSQL_USER_KEY])),
        "password": decrypt_local_machine_dpapi(str(encrypted[IRIS_MYSQL_PASSWORD_KEY])),
    }
    if not credentials["username"] or not credentials["password"]:
        raise SurvivalProjectLaunchError("The scoped Iris SQL identity is incomplete")
    return credentials


def resolve_runtime(server_root: Path, java: Path) -> Path:
    jar = server_root / "target" / JAR_NAME
    missing = [str(path) for path in (jar, java) if not path.is_file()]
    if missing:
        raise SurvivalProjectLaunchError(f"Survival Project runtime files are unavailable: {missing}")
    return jar


def build_environment(
    credentials: dict[str, str], *, database_host: str, database_port: int, database_name: str, bind_address: str
) -> dict[str, str]:
    if database_host != "127.0.0.1":
        raise SurvivalProjectLaunchError("The controlled AMP template permits only the 127.0.0.1 database host")
    if bind_address != "127.0.0.1":
        raise SurvivalProjectLaunchError("The controlled AMP template permits only the 127.0.0.1 bind address")
    environment = dict(os.environ)
    environment.update(
        {
            "SP_DB_URL": (
                f"jdbc:mysql://{database_host}:{database_port}/{database_name}"
                "?useSSL=false&serverTimezone=UTC"
            ),
            "SP_DB_USERNAME": credentials["username"],
            "SP_DB_PASSWORD": credentials["password"],
            "SP_BIND_ADDRESS": bind_address,
        }
    )
    return environment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Launch Survival Project through a scoped Iris SQL Vault.")
    parser.add_argument("--server-root", type=Path, default=Path(r"D:\SurvivalProject\Server"))
    parser.add_argument("--credential-store", type=Path, default=Path(r"D:\SurvivalProject\Server\config\iris-sql-vault.local.json"))
    parser.add_argument("--java", type=Path, default=Path(r"C:\Program Files\Java\jdk-25\bin\java.exe"))
    parser.add_argument("--database-host", default="127.0.0.1")
    parser.add_argument("--database-port", type=int, default=3306)
    parser.add_argument("--database-name", default="survivalproject")
    parser.add_argument("--bind-address", default="127.0.0.1")
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not (1 <= args.database_port <= 65535):
        raise SurvivalProjectLaunchError("The database port is invalid")
    if not args.database_host.strip() or not args.database_name.strip():
        raise SurvivalProjectLaunchError("The database endpoint is incomplete")
    server_root = args.server_root.resolve()
    jar = resolve_runtime(server_root, args.java.resolve())
    credentials = load_iris_database_credentials(args.credential_store.resolve())
    if args.check:
        print(json.dumps({"ok": True, "runtime": str(jar), "database": args.database_name, "bind_address": args.bind_address, "credential_keys": sorted((IRIS_MYSQL_USER_KEY, IRIS_MYSQL_PASSWORD_KEY)), "credential_provider": LOCAL_MACHINE_PROVIDER, "password_disclosed": False}))
        return 0
    environment = build_environment(credentials, database_host=args.database_host.strip(), database_port=args.database_port, database_name=args.database_name.strip(), bind_address=args.bind_address)
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen([str(args.java.resolve()), "-jar", str(jar)], cwd=server_root, env=environment)
        return int(process.wait())
    except KeyboardInterrupt:
        if process and process.poll() is None:
            process.terminate()
            try:
                return int(process.wait(timeout=30))
            except subprocess.TimeoutExpired:
                process.kill()
                return int(process.wait())
        return 130
    finally:
        environment["SP_DB_PASSWORD"] = ""
        credentials["password"] = ""


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SurvivalProjectLaunchError as exc:
        print(f"Survival Project launch failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
