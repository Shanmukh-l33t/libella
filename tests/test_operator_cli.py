"""Operator credential handling: no external services or assessments."""
import os
import pty
import secrets
import subprocess
import sys

import pytest

from libella.api import App
from libella.main import cli


def command(data_dir, *args):
    return [sys.executable, '-m', 'libella.main', '--data-dir', str(data_dir), *args]


def test_normal_start_does_not_log_token(tmp_path, monkeypatch, capsys):
    secret = secrets.token_urlsafe()
    monkeypatch.setenv('LIBELLA_TOKEN', secret)
    monkeypatch.setattr(sys, 'argv', command(tmp_path)[2:])
    captured = {}
    monkeypatch.setattr('uvicorn.run', lambda app, **kw: captured.update(kw))
    cli()
    output = capsys.readouterr()
    assert secret not in output.out + output.err
    assert captured['access_log'] is False  # stale clients may still send secrets in URLs


def test_operator_recovery_and_rotation(tmp_path, monkeypatch):
    monkeypatch.delenv('LIBELLA_SECRET_KEY', raising=False)
    original = App(tmp_path).token
    refused = subprocess.run(command(tmp_path, '--show-token'), capture_output=True)
    assert refused.returncode != 0 and b'terminal' in refused.stderr
    assert original.encode() not in refused.stdout + refused.stderr

    def read_interactively():
        master, slave = pty.openpty()
        try:
            result = subprocess.run(command(tmp_path, '--show-token'), stdout=slave, stderr=subprocess.PIPE)
            assert result.returncode == 0, result.stderr
            return os.read(master, 512).strip().decode()
        finally:
            os.close(master)
            os.close(slave)

    assert read_interactively() == original
    rotated = subprocess.run(command(tmp_path, '--rotate-token'), capture_output=True, check=True)
    updated = read_interactively()
    assert updated != original and updated == App(tmp_path).token
    for token in (original, updated):
        assert token.encode() not in rotated.stdout + rotated.stderr


@pytest.mark.parametrize('option', ['--rotate-token', '--show-token'])
def test_unknown_data_dir_not_initialized(tmp_path, option):
    directory = tmp_path / 'absent'
    result = subprocess.run(command(directory, option), capture_output=True)
    assert result.returncode != 0
    assert not directory.exists()
