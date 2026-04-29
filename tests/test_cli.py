"""End-to-end CLI tests.

These exercise the argparse-based CLI by monkeypatching getpass and
capturing stdout/stderr. They confirm the wiring between cli.py and
vault.py is correct.
"""

import pytest

from ombra import cli, crypto


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(crypto, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(crypto, "ARGON2_MEMORY_COST", 8)
    monkeypatch.setattr(crypto, "ARGON2_PARALLELISM", 1)


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "cli_vault.json"


def _queue_passwords(monkeypatch, *passwords):
    """Make getpass.getpass return the supplied passwords in order."""
    queue = list(passwords)

    def fake_getpass(prompt=""):
        return queue.pop(0)

    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)


def test_init_then_add_then_get(vault_path, monkeypatch, capsys):
    # init
    _queue_passwords(monkeypatch, "master-pw", "master-pw")
    rc = cli.main(["--vault", str(vault_path), "init"])
    assert rc == 0

    # add (uses prompt to enter the entry's password)
    _queue_passwords(monkeypatch, "master-pw", "github-pw!")
    rc = cli.main(["--vault", str(vault_path), "add", "github.com", "nick"])
    assert rc == 0

    # get
    _queue_passwords(monkeypatch, "master-pw")
    rc = cli.main(["--vault", str(vault_path), "get", "github.com"])
    assert rc == 0

    out = capsys.readouterr().out
    assert "github.com" in out
    assert "nick" in out
    assert "github-pw!" in out


def test_wrong_master_password_returns_error(vault_path, monkeypatch, capsys):
    _queue_passwords(monkeypatch, "right-pw", "right-pw")
    cli.main(["--vault", str(vault_path), "init"])

    _queue_passwords(monkeypatch, "wrong-pw")
    rc = cli.main(["--vault", str(vault_path), "list"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "authentication failed" in err.lower()


def test_get_missing_service_returns_error(vault_path, monkeypatch, capsys):
    _queue_passwords(monkeypatch, "pw", "pw")
    cli.main(["--vault", str(vault_path), "init"])

    _queue_passwords(monkeypatch, "pw")
    rc = cli.main(["--vault", str(vault_path), "get", "nonexistent"])
    assert rc == 1


def test_list_command_shows_services_in_order(vault_path, monkeypatch, capsys):
    _queue_passwords(monkeypatch, "pw", "pw")
    cli.main(["--vault", str(vault_path), "init"])

    for service in ["zeta.com", "alpha.com", "mu.com"]:
        _queue_passwords(monkeypatch, "pw", f"{service}-pw")
        cli.main(["--vault", str(vault_path), "add", service, "user"])

    capsys.readouterr()  # clear
    _queue_passwords(monkeypatch, "pw")
    rc = cli.main(["--vault", str(vault_path), "list"])
    assert rc == 0

    out = capsys.readouterr().out
    a_idx = out.index("alpha.com")
    m_idx = out.index("mu.com")
    z_idx = out.index("zeta.com")
    assert a_idx < m_idx < z_idx


def test_delete_with_yes_flag_skips_confirmation(vault_path, monkeypatch, capsys):
    _queue_passwords(monkeypatch, "pw", "pw")
    cli.main(["--vault", str(vault_path), "init"])

    _queue_passwords(monkeypatch, "pw", "secret")
    cli.main(["--vault", str(vault_path), "add", "github.com", "nick"])

    _queue_passwords(monkeypatch, "pw")
    rc = cli.main(["--vault", str(vault_path), "delete", "-y", "github.com"])
    assert rc == 0

    _queue_passwords(monkeypatch, "pw")
    rc = cli.main(["--vault", str(vault_path), "get", "github.com"])
    assert rc == 1


def test_change_master_password_via_cli(vault_path, monkeypatch, capsys):
    _queue_passwords(monkeypatch, "old", "old")
    cli.main(["--vault", str(vault_path), "init"])

    _queue_passwords(monkeypatch, "old", "secret")
    cli.main(["--vault", str(vault_path), "add", "github.com", "nick"])

    # change-password prompts: current, new, confirm-new
    _queue_passwords(monkeypatch, "old", "new", "new")
    rc = cli.main(["--vault", str(vault_path), "change-password"])
    assert rc == 0

    # New password works
    _queue_passwords(monkeypatch, "new")
    rc = cli.main(["--vault", str(vault_path), "get", "github.com"])
    assert rc == 0

    # Old password no longer works
    _queue_passwords(monkeypatch, "old")
    rc = cli.main(["--vault", str(vault_path), "get", "github.com"])
    assert rc == 1
