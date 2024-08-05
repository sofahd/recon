from OpenSSL import SSL
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