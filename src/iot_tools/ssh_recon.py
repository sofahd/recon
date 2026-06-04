"""
Deep SSH reconnaissance -- the paramiko half.

:class:`SshRecon` opens an authenticated SSH session to a discovered service and exposes a
``run(cmd) -> str`` callable backed by ``exec_command``; the actual harvest logic lives in the
paramiko-free :class:`ssh_harvest.SshHarvester`. paramiko is imported lazily by the caller
(``IotRecon``) so recon still imports on hosts without it.

**Safety:** only the read-only commands issued by ``SshHarvester`` are ever run; this class
adds no commands of its own beyond the handshake.
"""
import paramiko

from iot_tools.ssh_harvest import SshHarvester


class SshRecon:
    """Authenticated SSH harvest of a single host/port."""

    def __init__(self, host, port, username, password=None, key_file=None,
                 timeout=15, command_timeout=12, logger=None):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.command_timeout = command_timeout
        self.logger = logger

    def harvest(self):
        """Connect, harvest, and return the persona/files/listings/commands contract plus the
        server's banner. Always closes the connection."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "banner_timeout": self.timeout,
            "auth_timeout": self.timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if self.key_file:
            connect_kwargs["key_filename"] = self.key_file
        if self.password:
            connect_kwargs["password"] = self.password

        client.connect(**connect_kwargs)
        try:
            banner = client.get_transport().remote_version
            data = SshHarvester(run=self._runner(client)).harvest()
            # nmap is the canonical banner source downstream; include ours for completeness.
            data["banner"] = banner
            return data
        finally:
            client.close()

    def _runner(self, client):
        def run(command):
            _stdin, stdout, _stderr = client.exec_command(command, timeout=self.command_timeout)
            return stdout.read().decode("utf-8", errors="replace")
        return run
