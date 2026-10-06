"""`authyouragent vault ...`: run the browser vault with one command.

    authyouragent vault up --agent-id ag_... --key ./agent.pem
    authyouragent vault status
    authyouragent vault down        # signs out of every site first, then stops
    authyouragent vault env         # the MCP server's env block

An agent on another machine: publish the API on a VPN address
(`--listen 100.x.y.z`, e.g. Tailscale or WireGuard), or with TLS on any
address (`--listen 0.0.0.0 --tls`). The vault refuses to send its token in
clear text over anything else. `vault env` prints what to copy to the agent.

Uses Docker. Chromium's own sandbox is always on (with the seccomp profile
shipped in this package). If Docker has gVisor registered as a runtime
("runsc"), the vault also runs inside gVisor, which puts its own kernel between
the browser and the host's. Linux only; Docker Desktop on macOS/Windows uses
the seccomp profile alone.

Everything the vault needs lives in ~/.authyouragent/vault (token, a copy of
the agent key readable by the vault user, the crash record volume).
"""
import argparse
import ipaddress
import json
import re
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
TLS_PORT = 7443
VAULT_UID = 10001
# private ranges a VPN uses: plain HTTP is allowed there (the VPN encrypts it)
VPN_NETS = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fd00::/8")]


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


def _listen_plan(listen, tls, tls_names):
    """Where to publish the API besides 127.0.0.1:7801. Returns a list of
    `-p` values. Plain HTTP only on a VPN/private address; anything else
    (0.0.0.0, a public address, a host name) needs --tls."""
    if not listen:
        if tls:
            _die("--tls needs --listen ADDRESS (the address other machines reach this one on)")
        return []
    try:
        ip = ipaddress.ip_address(listen.strip("[]"))
    except ValueError:
        _die(f"--listen takes an IP address of this machine, not {listen!r}")
    if ip.is_loopback:
        return []
    bind = f"[{ip}]" if ip.version == 6 else str(ip)
    if tls:
        if ip.is_unspecified and not tls_names:
            _die("--listen 0.0.0.0 --tls needs --tls-name (the name or address the agent connects to)")
        return [f"{bind}:{TLS_PORT}:{TLS_PORT}"]
    if ip.is_unspecified or not any(ip in n for n in VPN_NETS):
        _die(f"{listen} is not a VPN or private address: the vault token would cross the network in "
             f"clear text. Add --tls, or listen on a VPN address (Tailscale 100.x, WireGuard 10.x).")
    return [f"{bind}:{PORT}:{PORT}"]


def _tls_files(names, cert=None, key=None):
    """The vault's TLS certificate and key, in HOME/tls (readable by the vault
    user). Your own with --tls-cert/--tls-key, otherwise a self-signed one for
    `names`, made once and kept; a new name makes a new one."""
    d = HOME / "tls"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o755)
    if cert or key:
        if not (cert and key):
            _die("--tls-cert and --tls-key go together")
        _vault_copy(Path(cert).expanduser(), "tls/cert.pem")
        _vault_copy(Path(key).expanduser(), "tls/key.pem")
        return d
    names = sorted(set(names))
    stamp = d / "names.json"
    if (d / "cert.pem").is_file() and (d / "key.pem").is_file() and stamp.is_file() \
            and json.loads(stamp.read_text()) == names:
        return d
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    alt = []
    for n in names:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            alt.append(x509.DNSName(n))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "authyouragent vault")])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=825))
         .add_extension(x509.SubjectAlternativeName(alt), critical=False)
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .sign(k, hashes.SHA256()))
    for name, data in (("key.pem", k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption())),
                       ("cert.pem", c.public_bytes(serialization.Encoding.PEM))):
        f = d / name
        if f.exists():
            f.chmod(0o600)
        f.write_bytes(data)
        try:
            os.chown(f, VAULT_UID, VAULT_UID)
            f.chmod(0o400 if name == "key.pem" else 0o444)
        except PermissionError:
            f.chmod(0o644)
    stamp.write_text(json.dumps(names))
    return d


def _fingerprint(cert_file):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    c = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
    return c.fingerprint(hashes.SHA256()).hex(":").upper()


def _remote_file():
    return HOME / "remote.json"


def start(agent_id, key, cloud="https://authyouragent.com", image=IMAGE, gvisor="auto",
          size="412x860", scale="2", pull=True, log=None, bitwarden=None,
          listen=None, tls=False, tls_names=(), tls_cert=None, tls_key=None):
    """Start the vault, or wait for it if its container is already running.
    Returns "started" or "running". Raises VaultError. Used by `vault up` and
    by the MCP server when the vault is needed and not running; `log` gets
    progress lines (the MCP server sends them to stderr, never stdout).
    `bitwarden`: path of a password manager config (see vault/bitwarden.py);
    default AYA_BITWARDEN_FILE, or the copy kept from the last `vault up`.
    `listen`/`tls`: also publish the API for an agent on another machine
    (see the module docstring); the default is this machine only."""
    log = log or (lambda *a: None)
    if not agent_id or not key:
        _die("need --agent-id and --key (or AYA_AGENT_ID / AYA_KEY_FILE)")
    if _running():
        # e.g. Docker is restarting it after a reboot: give it time to come up
        if not _wait_ready(_token()):
            _die(f"the vault container is running but not answering; see `docker logs {NAME}`")
        return "running"
    publish = _listen_plan(listen, tls, tls_names)
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
    for x in publish:
        args += ["-p", x]
    remote = None
    if listen and publish:
        if tls:
            names = list(tls_names) or [listen]
            d = _tls_files(names, tls_cert, tls_key)
            args += ["-v", f"{d}:/run/secrets/tls:ro", "-e", "VAULT_TLS_CERT=/run/secrets/tls/cert.pem",
                     "-e", "VAULT_TLS_KEY=/run/secrets/tls/key.pem"]
            host = names[0]
            host = f"[{host}]" if ":" in host else host
            remote = {"url": f"https://{host}:{TLS_PORT}", "ca_file": None if tls_cert else str(d / "cert.pem"),
                      "fingerprint": _fingerprint(d / "cert.pem")}
        else:
            host = f"[{listen}]" if ":" in listen else listen
            remote = {"url": f"http://{host}:{PORT}"}
    f = _remote_file()
    if remote:
        f.write_text(json.dumps(remote, indent=2) + "\n")
    elif f.exists():
        f.unlink()
    bw = bitwarden or os.environ.get("AYA_BITWARDEN_FILE")
    if bw:
        args += ["-v", f"{_bitwarden_copy(bw)}:/run/secrets/bitwarden.json:ro"]
    elif (HOME / "bitwarden.json").is_file():
        args += ["-v", f"{HOME / 'bitwarden.json'}:/run/secrets/bitwarden.json:ro"]
    # Trusted sites: a directory (not a file) so edits reach the running vault
    args += ["-v", f"{_trust_dir()}:/run/secrets/trust:ro", "-e", "VAULT_TRUST_FILE=/run/secrets/trust/trusted.json"]
    if use_gvisor:
        args += ["--runtime", "runsc"]
    _docker(*args, image)
    if not _wait_ready(token):
        _die(f"started but not answering; see `docker logs {NAME}`")
    log(f"vault running on 127.0.0.1:{PORT}  (browser sandbox: on, gVisor: {'on' if use_gvisor else 'off'})")
    if remote:
        log(f"also reachable at {remote['url']}" + (f"  (certificate SHA-256 {remote['fingerprint']})"
                                                    if remote.get("fingerprint") else "  (VPN only)"))
    return "started"


TRUST_HELP = """Trusted sites: your own exceptions to the vault's rules.
  authyouragent vault trust                      list them
  authyouragent vault trust example.com --no-approvals
        clicks on example.com stop asking you each time
  authyouragent vault trust 192.168.1.20:8123 --private
        the browser may open that host on your own network
  authyouragent vault trust example.com --remove
Saved passwords stay hidden from the agent either way. Each entry still asks
you once on your phone per session before it takes effect, so an agent that
edits the file cannot use it on its own. Loopback, link-local (cloud metadata)
and the vault itself stay blocked whatever the file says."""


def _trust_dir():
    d = HOME / "trust"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o755)
    return d


def _trust_file():
    return _trust_dir() / "trusted.json"


def trust_cmd(a):
    f = _trust_file()
    data = json.loads(f.read_text()) if f.is_file() else {"sites": {}}
    sites = data.setdefault("sites", {})
    if not a.site:
        if not sites:
            print("no trusted sites")
        for k, v in sorted(sites.items()):
            bits = []
            if v.get("approvals") is False:
                bits.append("no per-click approvals")
            if v.get("private"):
                bits.append("private network")
            print(f"{k}: {', '.join(bits) or 'nothing'}")
        return
    key = a.site.strip().lower()
    for pre in ("https://", "http://"):
        if key.startswith(pre):
            key = key[len(pre):]
    key = key.split("/")[0]
    if not re.fullmatch(r"[a-z0-9.-]+(:\d{1,5})?|\[[0-9a-f:]+\](:\d{1,5})?", key) or key.split(":")[0] == "localhost":
        _die(f"not a host name: {a.site}")
    if a.remove:
        sites.pop(key, None)
    else:
        e = sites.get(key, {})
        if a.no_approvals:
            e["approvals"] = False
        if a.approvals:
            e.pop("approvals", None)
        if a.private:
            e["private"] = True
        if not (a.no_approvals or a.approvals or a.private):
            _die("say what to trust: --no-approvals and/or --private (or --remove)")
        sites[key] = e
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.chmod(tmp, 0o644)
    tmp.replace(f)
    print(f"saved {f}. Your phone asks once per session before it takes effect.")
    if _running() and "/run/secrets/trust" not in _docker("inspect", "-f", "{{json .Mounts}}", NAME,
                                                           check=False).stdout:
        print("The running vault was started before trusted sites existed: "
              "`authyouragent vault down` and `vault up` once to pick it up.")


def up(a):
    if _running():
        print(f"already running ({NAME}). `authyouragent vault down` first to restart.")
        return
    start(a.agent_id or os.environ.get("AYA_AGENT_ID"), a.key or os.environ.get("AYA_KEY_FILE"),
          cloud=a.cloud, image=a.image, gvisor=a.gvisor, size=a.size, scale=a.scale,
          pull=not a.no_pull, log=print, bitwarden=a.bitwarden,
          listen=a.listen, tls=a.tls, tls_names=a.tls_name or (), tls_cert=a.tls_cert, tls_key=a.tls_key)
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
    f = _remote_file()
    if f.is_file():
        r = json.loads(f.read_text())
        far = {"AYA_VAULT_URL": r["url"], "AYA_VAULT_TOKEN_FILE": "/path/on/the/agent/machine/vault.token",
               "AYA_VAULT_AUTOSTART": "0"}
        if r.get("ca_file"):
            far["AYA_VAULT_CA_FILE"] = "/path/on/the/agent/machine/vault-cert.pem"
        print("\nOn the agent's machine:")
        print(json.dumps(far, indent=2))
        print(f"Copy {HOME / 'token'} there as the token file" +
              (f", and {r['ca_file']} as the certificate file" if r.get("ca_file") else "") +
              (f".\nCertificate SHA-256: {r['fingerprint']}" if r.get("fingerprint") else ".") +
              "\nKeep both private; anyone with the token can drive the browser.")


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
    u.add_argument("--listen", metavar="ADDRESS",
                   help="also serve the API on this address of this machine, for an agent elsewhere: "
                        "a VPN address (Tailscale 100.x, WireGuard 10.x) for plain HTTP, any address with --tls")
    u.add_argument("--tls", action="store_true", help=f"serve it over TLS on port {TLS_PORT} (self-signed unless --tls-cert)")
    u.add_argument("--tls-name", action="append", metavar="NAME",
                   help="name or address the agent connects to (repeatable; default: the --listen address)")
    u.add_argument("--tls-cert", help="your own certificate (PEM) instead of a self-signed one")
    u.add_argument("--tls-key", help="its private key (PEM)")
    u.set_defaults(fn=up)
    sub.add_parser("down", help="sign out of every site, then stop").set_defaults(fn=down)
    sub.add_parser("status").set_defaults(fn=status)
    t = sub.add_parser("trust", help="trusted sites (your exceptions to the vault's rules)",
                       description=TRUST_HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    t.add_argument("site", nargs="?")
    t.add_argument("--no-approvals", action="store_true", help="clicks on this site stop asking you each time")
    t.add_argument("--approvals", action="store_true", help="ask before clicks again")
    t.add_argument("--private", action="store_true", help="allow this host on your own network")
    t.add_argument("--remove", action="store_true")
    t.set_defaults(fn=trust_cmd)
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
