import socket
from typing import Optional


class SslCertInfoRetriever:
    """
    This class is designed to retrieve information about the SSL certificate of an IoT device.
    This information is required, to recreate the cert later on.
    """

    def __init__(self, logger) -> None:
        """
        Constructor for SslCertInfoRetriever class.
        :param logger: The logger to use.
        :type logger: SofahLogger
        """
        self.log = logger

    def process(self, ip_address:str, port:int) -> dict:
        """
        Process the retrieval of the SSL certificate information of an IoT device.
        :param ip_address: The IP-address of the IoT device.
        :type ip_address: str
        :param port: The port of the IoT device.
        :type port: int
        :return: dict, containing the SSL certificate information.
        """
        return self._retrieve_ssl_cert(ip_address, port)
    
    def _retrieve_ssl_cert(self, hostname:str, port:int) -> dict:
        """
        Retrieve the SSL certificate information of an IoT device.

        :param ip_address: The IP-address of the IoT device.
        :type ip_address: str
        :param port: The port of the IoT device.
        :type port: int
        :return: dict, containing the SSL certificate information.
        """
        # pyOpenSSL is only needed when we actually open a TLS connection. Importing it lazily
        # keeps the rest of recon (config validation, port scanning, crawling) importable and
        # testable without the TLS stack installed.
        from OpenSSL import SSL, crypto

        self.log.info(f'Retrieving SSL certificate information of {hostname}:{port}', method="recon.SslCertInfoRetriever.retrieve")

        ret_dict = {}
        try:
            context = SSL.Context(SSL.TLS_CLIENT_METHOD)
            conn = SSL.Connection(context, socket.socket()) 
            conn.connect((hostname,port))
            conn.set_connect_state()
            conn.do_handshake()
            cert = conn.get_peer_certificate()
            if cert:
                subject = cert.get_subject().get_components()
                if isinstance(subject, list):
                    ret_dict["subject"] = {}
                    for s in subject:
                        if isinstance(s, tuple) and s[0] in [b'CN', b'OU', b'O', b'L', b'ST', b'C']:
                            ret_dict["subject"][s[0].decode()] = s[1].decode()
                issuer = cert.get_issuer().get_components()
                if isinstance(issuer, list):
                    ret_dict["issuer"] = {}
                    for i in issuer:
                        if isinstance(i, tuple) and i[0] in [b'CN', b'OU', b'O', b'L', b'ST', b'C']:
                            ret_dict["issuer"][i[0].decode()] = i[1].decode()
                ret_dict["serial_number"] = cert.get_serial_number()
                ret_dict["version"] = cert.get_version()
                ret_dict["not_before"] = cert.get_notBefore().decode()
                ret_dict["not_after"] = cert.get_notAfter().decode()

                # Extra material so cert_forge can clone the original more closely: SANs,
                # signature algorithm and key type/size. All best-effort -- any field that
                # can't be read is simply omitted, and the forge tolerates its absence.
                try:
                    ret_dict["signature_algorithm"] = cert.get_signature_algorithm().decode(errors="ignore")
                except Exception:
                    pass
                try:
                    pubkey = cert.get_pubkey()
                    ret_dict["key_size"] = pubkey.bits()
                    ret_dict["key_type"] = {crypto.TYPE_RSA: "RSA", crypto.TYPE_DSA: "DSA"}.get(pubkey.type(), "EC")
                except Exception:
                    pass
                sans = self._extract_subject_alt_names(cert)
                if sans:
                    ret_dict["subject_alt_names"] = sans

                self.log.info(f'Successfully retrieved SSL certificate information of {hostname}:{port}', method="recon.SslCertInfoRetriever.retrieve")
            else:
                self.log.error(f'No certificate found for {hostname}:{port}', method="recon.SslCertInfoRetriever.retrieve")
        except Exception as e:
            self.log.error(f'Error retrieving SSL certificate information of {hostname}:{port}: {e}', method="recon.SslCertInfoRetriever")
            
        finally:
            try:
                conn.shutdown()
                conn.close()
            except:
                pass

        return ret_dict

    def _extract_subject_alt_names(self, cert) -> list:
        """
        Pull the subjectAltName entries off an X509 cert as a list like
        ``["DNS:device.local", "IP:192.0.2.10"]`` (pyOpenSSL renders IPs as "IP Address:",
        which is normalised to "IP:" so cert_forge can parse them uniformly). Returns ``[]``
        when the cert has no SAN extension.

        :param cert: the peer X509 certificate
        :return: list of "TYPE:value" SAN strings
        :rtype: list
        """

        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                return [
                    part.strip().replace("IP Address:", "IP:")
                    for part in str(ext).split(",")
                    if part.strip()
                ]
        return []