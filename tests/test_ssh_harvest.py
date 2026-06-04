"""
Tests for the deep SSH recon harvest logic (paramiko-free): the command set is shaped into
the persona/files/listings/commands contract, unreadable probes are skipped, and the optional
[Ssh] credentials reader / SSH detection behave.
"""
from configparser import ConfigParser

from iot_tools.ssh_harvest import SshHarvester, ssh_credentials_from_config
from iot_recon import IotRecon


def _device_run(cmd):
    """A stand-in for a real device's shell: exact-match responder for the harvest commands."""
    cmd = cmd.strip()
    if cmd == "uname -a":
        return "Linux cam-01 3.10.0 #1 SMP armv7l GNU/Linux\n"
    if cmd == "uname -m":
        return "armv7l\n"
    if cmd == "hostname":
        return "cam-01\n"
    if cmd == "whoami":
        return "root\n"
    if cmd.startswith("cat /etc/passwd"):
        return "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\n"
    if cmd.startswith("cat /etc/shadow"):
        return ""  # logged in non-root -> permission denied -> empty
    if cmd.startswith("cat /etc/os-release"):
        return "NAME=Buildroot\nVERSION=2019.02\n"
    if cmd.startswith("cat "):
        return ""
    if cmd == "ls -la /":
        return ("total 16\n"
                "drwxr-xr-x   17 root root 4096 Jan  1 00:00 .\n"
                "drwxr-xr-x   17 root root 4096 Jan  1 00:00 ..\n"
                "drwxr-xr-x    2 root root 4096 Jan  1 00:00 bin\n"
                "drwxr-xr-x    3 root root 4096 Jan  1 00:00 etc\n"
                "lrwxrwxrwx    1 root root   11 Jan  1 00:00 init -> bin/busybox\n")
    if cmd.startswith("ls -la /bin"):
        return ("total 8\n"
                "-rwxr-xr-x    1 root root 900000 Jan  1 00:00 busybox\n")
    if cmd.startswith("ls -la "):
        return ""
    if cmd.startswith("ps "):
        return "  PID USER COMMAND\n    1 root /sbin/init\n  900 root telnetd\n"
    if cmd.startswith("ifconfig"):
        return "eth0  Link encap:Ethernet  HWaddr AA:BB:CC:DD:EE:FF\n"
    if cmd.startswith("netstat"):
        return "tcp 0 0 0.0.0.0:23 0.0.0.0:* LISTEN\n"
    return ""


def test_harvest_builds_persona():
    data = SshHarvester(run=_device_run).harvest()
    persona = data["persona"]
    assert persona["uname"].startswith("Linux cam-01")
    assert persona["machine"] == "armv7l"
    assert persona["hostname"] == "cam-01"
    assert persona["username"] == "root"


def test_harvest_clones_readable_files_and_skips_unreadable():
    data = SshHarvester(run=_device_run).harvest()
    assert "root:x:0:0" in data["files"]["/etc/passwd"]
    assert "/etc/os-release" in data["files"]
    assert "/etc/shadow" not in data["files"]  # empty -> skipped


def test_harvest_clones_directory_listings():
    data = SshHarvester(run=_device_run).harvest()
    root = data["listings"]["/"]
    assert root["names"] == ["bin", "etc", "init"]   # '.'/'..' dropped, symlink name kept
    assert "init -> bin/busybox" in root["raw"]
    assert data["listings"]["/bin"]["names"] == ["busybox"]


def test_harvest_clones_command_output():
    data = SshHarvester(run=_device_run).harvest()
    assert "telnetd" in data["commands"]["ps"]
    assert "AA:BB:CC:DD:EE:FF" in data["commands"]["ifconfig"]
    assert "0.0.0.0:23" in data["commands"]["netstat"]


def test_harvest_file_size_cap():
    huge = "A" * 5000
    harvester = SshHarvester(run=lambda cmd: huge if cmd.startswith("cat /etc/passwd") else "",
                             max_file_bytes=1000)
    data = harvester.harvest()
    assert len(data["files"]["/etc/passwd"]) == 1000


def test_failed_probe_does_not_abort_harvest():
    def flaky(cmd):
        if cmd == "uname -a":
            raise RuntimeError("connection reset")
        if cmd == "hostname":
            return "cam-01"
        return ""
    data = SshHarvester(run=flaky).harvest()
    assert data["persona"]["hostname"] == "cam-01"  # harvest continued past the failure


# -- optional [Ssh] credentials ------------------------------------------------------ #

def _cfg(options=None):
    cfg = ConfigParser()
    if options is not None:
        cfg.add_section("Ssh")
        for key, value in options.items():
            cfg.set("Ssh", key, value)
    return cfg


def test_credentials_absent_when_no_section():
    assert ssh_credentials_from_config(_cfg(None)) is None


def test_credentials_absent_when_disabled():
    assert ssh_credentials_from_config(_cfg({"enabled": "false", "username": "root", "password": "x"})) is None


def test_credentials_absent_without_username():
    assert ssh_credentials_from_config(_cfg({"password": "x"})) is None


def test_credentials_parsed():
    creds = ssh_credentials_from_config(_cfg({"username": "root", "password": "root", "timeout": "20"}))
    assert creds == {"username": "root", "password": "root", "key_file": None, "timeout": 20}


def test_credentials_key_file():
    creds = ssh_credentials_from_config(_cfg({"username": "root", "key_file": "/k/id_rsa"}))
    assert creds["key_file"] == "/k/id_rsa" and creds["password"] is None


# -- SSH detection (kept identical to EnNorm._is_ssh) -------------------------------- #

def test_is_ssh_port_by_service_name():
    assert IotRecon._is_ssh_port({"service_version": "ssh", "banner": None})


def test_is_ssh_port_by_banner():
    assert IotRecon._is_ssh_port({"service_version": None, "banner": "SSH-2.0-OpenSSH_7.4"})


def test_is_ssh_port_rejects_http():
    assert not IotRecon._is_ssh_port({"service_version": "http", "banner": "Apache"})
