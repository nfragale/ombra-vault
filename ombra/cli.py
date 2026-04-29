"""Command-line interface for Ombra Vault.

Commands
--------
* init             Create a new vault.
* add SERVICE      Add a new credential.
* get SERVICE      Decrypt and print a credential.
* list             List stored service names.
* delete SERVICE   Remove a credential.
* change-password  Re-key the vault with a new master password.

All passwords are read via getpass so they never appear on screen or in
shell history. A non-zero exit code is returned on any failure.
"""

from __future__ import annotations

import argparse
import getpass
import secrets
import string
import sys
from pathlib import Path

from . import vault as vault_mod
from .errors import (
    AuthenticationError,
    EntryExistsError,
    EntryNotFoundError,
    OmbraError,
    VaultCorruptedError,
    VaultExistsError,
    VaultNotFoundError,
)

DEFAULT_VAULT_PATH = Path.home() / ".ombra" / "vault.json"


# ---------- helpers ----------

def _prompt_master(confirm: bool = False, prompt: str = "Master password: ") -> str:
    """Securely prompt for a master password, optionally with confirmation."""
    pw = getpass.getpass(prompt)
    if not pw:
        print("Error: master password cannot be empty.", file=sys.stderr)
        sys.exit(2)
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            print("Error: passwords do not match.", file=sys.stderr)
            sys.exit(2)
    return pw


def _generate_password(length: int = 20) -> str:
    """Generate a cryptographically random password using `secrets`.

    Uses letters + digits + a curated punctuation set (avoids characters
    that commonly cause shell or website breakage like quotes/backticks).
    """
    if length < 8:
        raise ValueError("Generated passwords must be at least 8 characters.")
    safe_punct = "!@#$%^&*()-_=+[]{};:,.?/"
    alphabet = string.ascii_letters + string.digits + safe_punct
    # Loop until we get at least one of each class so the password is
    # unlikely to fail "must contain a symbol" rules.
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw)
                and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(c in safe_punct for c in pw)):
            return pw


# ---------- command handlers ----------

def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.vault)
    if path.exists():
        print(f"Error: a vault already exists at {path}.", file=sys.stderr)
        return 1
    print(f"Creating new vault at {path}")
    print("Choose a strong master password. This cannot be recovered if forgotten.")
    master = _prompt_master(confirm=True)
    vault_mod.create_vault(path, master)
    print(f"Vault created. File permissions set to 0600.")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    master = _prompt_master()
    v = vault_mod.open_vault(args.vault, master)

    if args.generate:
        password = _generate_password(length=args.length)
        print(f"Generated password ({args.length} chars): {password}")
    else:
        password = getpass.getpass(f"Password for {args.service}: ")
        if not password:
            print("Error: password cannot be empty.", file=sys.stderr)
            return 2

    v.add(args.service, args.username, password)
    v.save()
    print(f"Added entry for {args.service!r}.")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    master = _prompt_master()
    v = vault_mod.open_vault(args.vault, master)
    username, password = v.get(args.service)
    print(f"Service:  {args.service}")
    print(f"Username: {username}")
    print(f"Password: {password}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    master = _prompt_master()
    v = vault_mod.open_vault(args.vault, master)
    services = v.list_services()
    if not services:
        print("(vault is empty)")
        return 0
    print(f"{len(services)} entr{'y' if len(services) == 1 else 'ies'}:")
    for s in services:
        print(f"  - {s}")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    master = _prompt_master()
    v = vault_mod.open_vault(args.vault, master)
    if not args.yes:
        confirm = input(f"Delete entry for {args.service!r}? [y/N] ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Aborted.")
            return 0
    v.delete(args.service)
    v.save()
    print(f"Deleted entry for {args.service!r}.")
    return 0


def cmd_change_password(args: argparse.Namespace) -> int:
    print("Verifying current master password...")
    current = _prompt_master(prompt="Current master password: ")
    v = vault_mod.open_vault(args.vault, current)
    print("Verified. Enter the new master password.")
    new = _prompt_master(confirm=True, prompt="New master password: ")
    vault_mod.change_master_password(v, new)
    print("Master password changed. All entries re-encrypted under the new key.")
    return 0


# ---------- argparse plumbing ----------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ombra",
        description="Ombra Vault — a local-only encrypted password manager.",
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=DEFAULT_VAULT_PATH,
        help=f"Path to the vault file (default: {DEFAULT_VAULT_PATH}).",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_init = sub.add_parser("init", help="Create a new vault.")
    p_init.set_defaults(func=cmd_init)

    p_add = sub.add_parser("add", help="Add a new credential.")
    p_add.add_argument("service", help="Service name (e.g. github.com).")
    p_add.add_argument("username", help="Username or email for the service.")
    p_add.add_argument(
        "-g", "--generate", action="store_true",
        help="Generate a strong random password instead of prompting.",
    )
    p_add.add_argument(
        "-l", "--length", type=int, default=20,
        help="Length of generated password (default: 20).",
    )
    p_add.set_defaults(func=cmd_add)

    p_get = sub.add_parser("get", help="Retrieve a credential.")
    p_get.add_argument("service", help="Service name to retrieve.")
    p_get.set_defaults(func=cmd_get)

    p_list = sub.add_parser("list", help="List stored service names.")
    p_list.set_defaults(func=cmd_list)

    p_del = sub.add_parser("delete", help="Delete a credential.")
    p_del.add_argument("service", help="Service name to delete.")
    p_del.add_argument("-y", "--yes", action="store_true", help="Skip confirmation.")
    p_del.set_defaults(func=cmd_delete)

    p_chg = sub.add_parser("change-password", help="Change the master password.")
    p_chg.set_defaults(func=cmd_change_password)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except VaultNotFoundError as e:
        print(f"Error: {e} Try `ombra init` first.", file=sys.stderr)
        return 1
    except VaultExistsError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except AuthenticationError:
        # Deliberately generic — don't reveal whether it was a wrong
        # password or tampering.
        print("Error: authentication failed.", file=sys.stderr)
        return 1
    except VaultCorruptedError as e:
        print(f"Error: vault is corrupted or malformed: {e}", file=sys.stderr)
        return 1
    except EntryNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except EntryExistsError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except OmbraError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
