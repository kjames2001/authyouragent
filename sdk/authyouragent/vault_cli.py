"""`authyouragent vault ...`: run the browser vault with one command.

    authyouragent vault up --agent-id ag_... --key ./agent.pem
    authyouragent vault status
    authyouragent vault down        # signs out of every site first, then stops
    authyouragent vault env         # the MCP server's env block

Uses Docker. Chromium's own sandbox is always on (with the seccomp profile
shipped in this package). If Docker has gVisor registered as a runtime
("runsc"), the vault also runs inside gVisor, which puts its own kernel between
the browser and the host's. Linux only; Docker Desktop on macOS/Windows uses
the seccomp profile alone.

Everything the vault needs lives in ~/.authyouragent/vault (token, a copy of
the agent key readable by the vault user, the crash record volume).
"""
import argparse
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time
from importlib import resources
from pathlib import Path
from typing import NoReturn

IMAGE = os.environ.get("AYA_VAULT_IMAGE", "ghcr.io/kjames2001/authyouragent-vault:latest")
NAME = "authyouragent-vault"
HOME = Path(os.environ.get("AYA_VAULT_HOME", Path.home() / ".authyouragent" / "vault"))
PORT = 7801
VAULT_UID = 10001


class VaultError(RuntimeError):
    """Starting or reaching the vault failed; the message says why."""


def _die(msg) -> NoReturn:
    raise VaultError(msg)


def _docker(*args, check=True, capture=True):
    try:
        r = subprocess.run(["docker", *args], capture_output=capture, text=True)
    except FileNotFoundError:
        _die("Docker is not installed. Get it from https://docs.docker.com/get-docker/")
    if check and r.returncode != 0:
        _die(f"docker {args[0]} failed: {(r.stderr or r.stdout).strip()[:400]}")
    return r


def _has_gvisor():
    r = _docker("info", "--format", "{{json .Runtimes}}", check=False)
    try:
        return "runsc" in json.loads(r.stdout or "{}")
    except ValueError:
        return False


def _running():
    r = _docker("inspect", "-f", "{{.State.Running}}", NAME, check=False)
    return r.returncode == 0 and r.stdout.strip() == "true"


def _token():
    p = HOME / "token"
    if not p.exists():
        HOME.mkdir(parents=True, exist_ok=True)
        p.write_text(secrets.token_urlsafe(32))
        p.chmod(0o600)
    return p.read_text().strip()


def _seccomp():
    p = HOME / "seccomp.json"
    p.write_text(resources.files("authyouragent").joinpath("vault_seccomp.json").read_text())
    return p


def _vault_copy(src, name):
    """Copy src to HOME/name, readable only by the vault user (uid 10001;
    falls back to 0644 when we cannot chown, e.g. rootless). When src already
    is that copy (from an earlier `vault up`), it is used as it is."""
    dst = HOME / name
    if dst.exists() and src.resolve() == dst.resolve():
        return dst
    shutil.copyfile(src, dst)
    try:
        os.chown(dst, VAULT_UID, VAULT_UID)
        dst.chmod(0o400)
    except PermissionError:
        dst.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    return dst


def _key_copy(key):
    """The vault runs as uid 10001. Give it its own copy of the key."""
    src = Path(key).expanduser()
    if not src.is_file():
        _die(f"agent key not found: {src}")
    return _vault_copy(src, "agent.pem")


def _bitwarden_copy(path):
    """The password manager config, readable only by the vault user."""
    src = Path(path).expanduser()
    if not src.is_file():
        _die(f"bitwarden config not found: {src}")
    try:
        cfg = json.loads(src.read_text())
    except ValueError as e:
        _die(f"bitwarden config is not valid JSON: {e}")
    missing = [k for k in ("url", "email", "master_password") if not cfg.get(k)]
    if missing:
        _die(f"bitwarden config is missing: {', '.join(missing)}")
    return _vault_copy(src, "bitwarden.json")


def _state_dir():
    d = HOME / "state"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chown(d, VAULT_UID, VAULT_UID)
    except PermissionError:
        d.chmod(0o777)
    return d


def _wait_ready(token, seconds=60):
    import httpx
    end = time.time() + seconds
    while time.time() < end:
        try:
            r = httpx.get(f"http://127.0.0.1:{PORT}/status",
                          headers={"Authorization": f"Bearer {token}"}, timeout=3)
            if r.status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return False


def start(agent_id, key, cloud="https://authyouragent.com", image=IMAGE, gvisor="auto",
          size="412x860", scale="2", pull=True, log=None, bitwarden=None):
    """Start the vault, or wait for it if its container is already running.
    Returns "started" or "running". Raises VaultError. Used by `vault up` and
    by the MCP server when the vault is needed and not running; `log` gets
    progress lines (the MCP server sends them to stderr, never stdout).
    `bitwarden`: path of a password manager config (see vault/bitwarden.py);
    default AYA_BITWARDEN_FILE, or the copy kept from the last `vault up`."""
    log = log or (lambda *a: None)
    if not agent_id or not key:
        _die("need --agent-id and --key (or AYA_AGENT_ID / AYA_KEY_FILE)")
    if _running():
        # e.g. Docker is restarting it after a reboot: give it time to come up
        if not _wait_ready(_token()):
            _die(f"the vault container is running but not answering; see `docker logs {NAME}`")
        return "running"
    _docker("rm", "-f", NAME, check=False)
    token = _token()
    use_gvisor = {"auto": _has_gvisor(), "on": True, "off": False}[gvisor]
    if gvisor == "on" and not _has_gvisor():
        _die("--gvisor on, but Docker has no 'runsc' runtime. See https://gvisor.dev/docs/user_guide/install/")
    if pull:
        log(f"pulling {image} ...")
        r = _docker("pull", "-q", image, check=False)
        if r.returncode != 0:
            if _docker("image", "inspect", image, check=False).returncode != 0:
                _die(f"docker pull failed: {(r.stderr or r.stdout).strip()[:400]}")
            log("pull failed; using the copy already on this machine")
    args = ["run", "-d", "--name", NAME, "--restart", "unless-stopped",
            "--shm-size=1g", "--stop-timeout", "120",
            "--security-opt", f"seccomp={_seccomp()}",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "-e", f"VAULT_TOKEN={token}", "-e", f"AYA_AGENT_ID={agent_id}",
            "-e", f"AYA_CLOUD={cloud}", "-e", f"VAULT_SIZE={size}", "-e", f"VAULT_SCALE={scale}",
            "-v", f"{_key_copy(key)}:/run/secrets/agent.pem:ro",
            "-v", f"{_state_dir()}:/var/lib/vault",
            "-p", f"127.0.0.1:{PORT}:{PORT}"]
    bw = bitwarden or os.environ.get("AYA_BITWARDEN_FILE")
    if bw:
        args += ["-v", f"{_bitwarden_copy(bw)}:/run/secrets/bitwarden.json:ro"]
    elif (HOME / "bitwarden.json").is_file():
        args += ["-v", f"{HOME / 'bitwarden.json'}:/run/secrets/bitwarden.json:ro"]
    if use_gvisor:
        args += ["--runtime", "runsc"]
    _docker(*args, image)
    if not _wait_ready(token):
        _die(f"started but not answering; see `docker logs {NAME}`")
    log(f"vault running on 127.0.0.1:{PORT}  (browser sandbox: on, gVisor: {'on' if use_gvisor else 'off'})")
    return "started"


def up(a):
    if _running():
        print(f"already running ({NAME}). `authyouragent vault down` first to restart.")
        return
    start(a.agent_id or os.environ.get("AYA_AGENT_ID"), a.key or os.environ.get("AYA_KEY_FILE"),
          cloud=a.cloud, image=a.image, gvisor=a.gvisor, size=a.size, scale=a.scale,
          pull=not a.no_pull, log=print, bitwarden=a.bitwarden)
    print("MCP server env:")
    env(a, quiet=True)


def down(a):
    if _running():
        import httpx
        try:
            r = httpx.post(f"http://127.0.0.1:{PORT}/end_session", json={"why": "vault down"},
                           headers={"Authorization": f"Bearer {_token()}"}, timeout=150)
            for site, res in r.json().get("sign_out", {}).items():
                print(f"  {site}: {res}")
        except Exception as e:
            print(f"  could not sign out first ({type(e).__name__}); stopping anyway")
    _docker("rm", "-f", NAME, check=False)
    print("vault stopped")


def status(a):
    if not _running():
        print("not running")
        return
    rt = _docker("inspect", "-f", "{{.HostConfig.Runtime}}", NAME).stdout.strip()
    import httpx
    s = httpx.get(f"http://127.0.0.1:{PORT}/status", headers={"Authorization": f"Bearer {_token()}"},
                  timeout=5).json()
    print(json.dumps({"running": True, "gvisor": rt == "runsc", **s}, indent=2))


def env(a, quiet=False):
    block = {"AYA_VAULT_URL": f"http://127.0.0.1:{PORT}",
             "AYA_VAULT_TOKEN_FILE": str(HOME / "token")}
    if getattr(a, "agent_id", None):
        block["AYA_AGENT_ID"] = a.agent_id
    if getattr(a, "key", None):
        block["AYA_KEY_FILE"] = str(Path(a.key).expanduser().resolve())
    print(json.dumps(block, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="authyouragent vault", description="Run the Auth Your Agent browser vault.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("up", help="start the vault")
    u.add_argument("--agent-id")
    u.add_argument("--key", help="the agent's private key (PEM)")
    u.add_argument("--cloud", default=os.environ.get("AYA_CLOUD", "https://authyouragent.com"))
    u.add_argument("--image", default=IMAGE)
    u.add_argument("--gvisor", choices=("auto", "on", "off"), default="auto")
    u.add_argument("--size", default="412x860", help="page size in CSS px (phone-shaped by default)")
    u.add_argument("--scale", default="2")
    u.add_argument("--no-pull", action="store_true")
    u.add_argument("--bitwarden", help="password manager config (JSON) for fill_secret; kept for later starts")
    u.set_defaults(fn=up)
    sub.add_parser("down", help="sign out of every site, then stop").set_defaults(fn=down)
    sub.add_parser("status").set_defaults(fn=status)
    e = sub.add_parser("env", help="print the MCP server env block")
    e.add_argument("--agent-id")
    e.add_argument("--key")
    e.set_defaults(fn=env)
    a = ap.parse_args(argv)
    try:
        a.fn(a)
    except VaultError as e:
        print(f"authyouragent vault: {e}", file=sys.stderr)
        sys.exit(1)
    except BrokenPipeError:        # output piped into e.g. `head`
        pass
