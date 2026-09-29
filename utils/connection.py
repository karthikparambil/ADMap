import os
import socket
import ldap3
from ldap3 import Server, Connection, ALL, NTLM, KERBEROS, SIMPLE, ANONYMOUS
from ldap3.core.exceptions import LDAPException

from rich.console import Console

console = Console()


class ADConnection:
    """Manages LDAP/LDAPS connections to an Active Directory Domain Controller."""

    def __init__(self, dc_host: str, domain: str, username: str = None,
                 password: str = None, ntlm_hash: str = None,
                 use_kerberos: bool = False, use_ssl: bool = False,
                 port: int = None, timeout: int = 10):
        self.dc_host = dc_host
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.use_kerberos = use_kerberos
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.port = port or (636 if use_ssl else 389)
        self.conn: Connection = None
        self.base_dn: str = self._build_base_dn(domain)
        self.server_info = None

    @staticmethod
    def _build_base_dn(domain: str) -> str:
        parts = domain.strip().split(".")
        return ",".join(f"DC={p}" for p in parts)

    def _resolve_dc(self) -> str:
        """Try to resolve the DC hostname; return IP if possible."""
        try:
            return socket.gethostbyname(self.dc_host)
        except socket.gaierror:
            return self.dc_host

    def _get_anonymous_conn(self, server: Server) -> Connection:
        return Connection(server, authentication=ANONYMOUS, auto_bind=True)

    def _get_simple_conn(self, server: Server) -> Connection:
        user = f"{self.domain}\\{self.username}" if self.username else ""
        return Connection(server, user=user, password=self.password or "",
                          authentication=SIMPLE, auto_bind=True)

    def _get_ntlm_conn(self, server: Server) -> Connection:
        """NTLM via plaintext password or pass-the-hash."""
        user = f"{self.domain}\\{self.username}"
        if self.ntlm_hash:
            lm_hash, nt_hash = ("", self.ntlm_hash) if ":" not in self.ntlm_hash else self.ntlm_hash.split(":", 1)
            password = f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}"
        else:
            password = self.password
        return Connection(server, user=user, password=password,
                          authentication=NTLM, auto_bind=True)

    def _get_kerberos_conn(self, server: Server) -> Connection:
        """Kerberos authentication (reads KRB5CCNAME from env for ccache)."""
        user = f"{self.username}@{self.domain.upper()}" if self.username else ""
        return Connection(server, user=user, authentication=KERBEROS, auto_bind=True)

    def connect(self) -> bool:
        """Establish the LDAP connection. Returns True on success."""
        dc_ip = self._resolve_dc()
        server = Server(dc_ip, port=self.port, use_ssl=self.use_ssl,
                        get_info=ALL, connect_timeout=self.timeout)
        try:
            if self.use_kerberos:
                self.conn = self._get_kerberos_conn(server)
            elif self.ntlm_hash:
                self.conn = self._get_ntlm_conn(server)
            elif self.username:
                self.conn = self._get_ntlm_conn(server)
            else:
                self.conn = self._get_anonymous_conn(server)

            self.server_info = server.info
            return True
        except LDAPException as e:
            console.print(f"[red][!] LDAP connection failed:[/red] {e}")
            return False
        except Exception as e:
            console.print(f"[red][!] Unexpected error during connect:[/red] {e}")
            return False

    def disconnect(self):
        if self.conn and self.conn.bound:
            self.conn.unbind()

    def search(self, search_filter: str, attributes: list,
               search_base: str = None) -> list:
        """
        Perform a paged LDAP search. Returns a list of entry dicts.
        """
        base = search_base or self.base_dn
        entries = []
        try:
            self.conn.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                paged_size=500,
            )
            entries = list(self.conn.entries)

            cookie = self.conn.result.get("controls", {}).get(
                "1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
            while cookie:
                self.conn.search(
                    search_base=base,
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=attributes,
                    paged_size=500,
                    paged_cookie=cookie,
                )
                entries.extend(self.conn.entries)
                cookie = self.conn.result.get("controls", {}).get(
                    "1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
        except Exception as e:
            console.print(f"[red][!] LDAP search error:[/red] {e}")
        return entries

    def is_connected(self) -> bool:
        return self.conn is not None and self.conn.bound

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
