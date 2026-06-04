"""
Deep SSH reconnaissance -- the paramiko-free half.

When recon is given credentials for a discovered SSH service it logs in and harvests a
*persona* of the real device so the SOFAH SSH pot can clone it faithfully: system identity
(uname/hostname/user), the contents of well-known config/identity files, directory listings,
and the output of common diagnostic commands (ps, ifconfig, netstat, ...).

``SshHarvester`` contains only the harvest *logic* -- which commands to run and how to shape
their output into the persona/files/listings/commands contract. It takes a ``run(cmd) -> str``
callable (provided by :class:`ssh_recon.SshRecon`, which owns the paramiko transport), so the
logic is unit-testable with a stub runner and recon imports without paramiko present.

**Safety:** every command issued is strictly READ-ONLY (``uname``/``cat``/``ls``/``ps``/...).
Nothing here writes to, modifies, or executes anything on the target device.
"""


# Identity/config files worth cloning. cat is attempted for each; unreadable ones (e.g.
# /etc/shadow when logged in non-root) simply come back empty and are skipped.
HARVEST_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hostname", "/etc/os-release",
    "/etc/issue", "/etc/issue.net", "/etc/motd", "/etc/resolv.conf",
    "/proc/version", "/proc/cpuinfo", "/proc/meminfo", "/proc/mounts",
]

# Directories whose `ls -la` is cloned so the pot's `ls` matches the real tree.
HARVEST_DIRS = [
    "/", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/local/bin",
    "/etc", "/home", "/root", "/var", "/var/log", "/tmp", "/lib", "/mnt", "/opt", "/dev",
]

# name -> command. Output is replayed verbatim by the pot for that command. The `|| ...`
# fallbacks cope with busybox vs coreutils vs iproute2 differences across IoT devices.
HARVEST_COMMANDS = {
    "ps": "ps aux 2>/dev/null || ps -ef 2>/dev/null || ps",
    "ifconfig": "ifconfig 2>/dev/null || ip addr 2>/dev/null",
    "netstat": "netstat -tlnp 2>/dev/null || netstat -tln 2>/dev/null || ss -tlnp 2>/dev/null",
    "free": "free -m 2>/dev/null || free 2>/dev/null",
    "mount": "mount 2>/dev/null",
    "uptime": "uptime 2>/dev/null",
    "w": "w 2>/dev/null || who 2>/dev/null",
    "id": "id 2>/dev/null",
    "lsmod": "lsmod 2>/dev/null",
    "df": "df -h 2>/dev/null || df 2>/dev/null",
    "busybox": "busybox 2>/dev/null || busybox --list 2>/dev/null",
}


def ssh_credentials_from_config(config):
    """Read the OPTIONAL ``[Ssh]`` credentials from a recon ``ConfigParser``.

    Returns ``{"username", "password", "key_file", "timeout"}`` when deep SSH harvest is
    configured, or ``None`` when it is not -- in which case recon still records the SSH banner
    (from nmap) but does not log in. The whole section is optional and ``_validate_config``
    never requires it; harvest is opt-in by providing a ``username`` (and a password or key).

    :param config: a ``configparser.ConfigParser`` (recon's loaded config).
    :return: credentials dict or ``None``.
    """
    if not config.has_section("Ssh"):
        return None
    if config.has_option("Ssh", "enabled") and not config.getboolean("Ssh", "enabled"):
        return None
    username = config.get("Ssh", "username", fallback="").strip()
    if not username:
        return None
    password = config.get("Ssh", "password", fallback="").strip() or None
    key_file = config.get("Ssh", "key_file", fallback="").strip() or None
    try:
        timeout = config.getint("Ssh", "timeout", fallback=15)
    except ValueError:
        timeout = 15
    return {"username": username, "password": password, "key_file": key_file, "timeout": timeout}


class SshHarvester:
    """Runs the harvest command set through an injected ``run`` callable and structures the
    output into ``{persona, files, listings, commands}``."""

    def __init__(self, run, max_file_bytes=131072, max_listing_entries=500):
        """
        :param run: callable taking a command string and returning its stdout as text.
        :param max_file_bytes: cap on a cloned file's size (defends against a huge /proc file).
        :param max_listing_entries: cap on entries parsed out of one directory listing.
        """
        self._run = run
        self.max_file_bytes = max_file_bytes
        self.max_listing_entries = max_listing_entries

    def harvest(self):
        """Run the full harvest. Returns the persona/files/listings/commands contract; any
        individual command that errors or returns nothing is just omitted."""
        return {
            "persona": self._harvest_persona(),
            "files": self._harvest_files(),
            "listings": self._harvest_listings(),
            "commands": self._harvest_commands(),
        }

    # -- sections -----------------------------------------------------------------------

    def _harvest_persona(self):
        persona = {}
        uname = self._safe("uname -a")
        if uname:
            persona["uname"] = uname
        machine = self._safe("uname -m")
        if machine:
            persona["machine"] = machine
        hostname = self._safe("hostname") or self._safe("uname -n")
        if hostname:
            persona["hostname"] = hostname
        whoami = self._safe("whoami")
        if whoami:
            persona["username"] = whoami
        return persona

    def _harvest_files(self):
        files = {}
        for path in HARVEST_FILES:
            content = self._safe(f"cat {path}", strip=False)
            if content:
                files[path] = content[: self.max_file_bytes]
        return files

    def _harvest_listings(self):
        listings = {}
        for directory in HARVEST_DIRS:
            raw = self._safe(f"ls -la {directory}", strip=False)
            if not raw:
                continue
            names = self._parse_ls_names(raw)
            listings[directory] = {"raw": raw, "names": names}
        return listings

    def _harvest_commands(self):
        commands = {}
        for name, command in HARVEST_COMMANDS.items():
            output = self._safe(command, strip=False)
            if output:
                commands[name] = output
        return commands

    # -- helpers ------------------------------------------------------------------------

    def _safe(self, command, strip=True):
        """Run a command, swallowing any error into an empty string so one failed probe never
        aborts the harvest."""
        try:
            output = self._run(command)
        except Exception:  # noqa: BLE001 - a failed probe must not abort the whole harvest
            return ""
        if output is None:
            return ""
        return output.strip() if strip else output.rstrip("\n")

    def _parse_ls_names(self, raw):
        """Pull the entry names out of an ``ls -la`` listing (excluding ``.``/``..`` and the
        ``total`` header), honouring the ``name -> target`` form for symlinks."""
        names = []
        for line in raw.splitlines():
            line = line.rstrip()
            if not line or line.startswith("total "):
                continue
            parts = line.split(None, 8)
            if len(parts) < 9 or len(parts[0]) < 1 or parts[0][0] not in "dlpscb-":
                continue
            name = parts[8]
            if " -> " in name:  # symlink: keep just the link name
                name = name.split(" -> ", 1)[0]
            if name in (".", ".."):
                continue
            names.append(name)
            if len(names) >= self.max_listing_entries:
                break
        return names
