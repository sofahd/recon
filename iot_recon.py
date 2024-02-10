from recon.iot_tools.port_scan import PortScan
from recon.iot_tools.api_crawler import ApiCrawler
from recon.utils.utils import load_config
import logging, sys
from typing import Union, Optional

class IotRecon:
    """
    Class used for Reconnaissance on IOT-devices.
    """

    def __init__(self, path:str):
        """
        Constructor for IotRecon class.
        """

        self.config = load_config(path)
        self.log = logging.Logger("IotRecon")
        self.log.setLevel(logging.INFO)  # Set the logging level as needed

        # Create a handler that writes log messages to stdout
        handler = logging.StreamHandler(sys.stdout)

        # Optionally, set a formatter for the handler
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        # Add the handler to the logger
        self.log.addHandler(handler)


    
    def _port_scan(self, ip_address:Union[str, list[str]], excl_ports:list[int] = None) -> dict:
        """
        Scan an IP-address for open ports.

        :param ip_address: The IP-address to scan.
        :type ip_address: str
        :param excl_ports: The ports to exclude from the scan.
        :type excl_ports: list[int]
        :return:
        """
        port_scan = PortScan(config=self.config, logger=self.log)
        
        return port_scan.scan(ip_address=ip_address, excl_ports=excl_ports)
        
        
    def _crawl_api(self, ip_address:str, port:int, endpoints:dict, output_path:str) -> None:
        """
        Crawl the API of an IoT device.

        :param ip_address: The IP-address of the IoT device.
        :type ip_address: str
        :param port: The port of the IoT device.
        :type port: int
        :param endpoints: The endpoints dict, containing the endpoints to crawl.
        :type endpoints: dict
        :param output_path: The path to save the output to.
        :type output_path: str
        :return:
        """

        api_crawler = ApiCrawler(config=self.config, logger=self.log)
        
        return api_crawler.crawl(ip_address=ip_address, port=port, endpoints=endpoints, output_path=output_path)
    
    
    def scan(self,
             ip_address:Union[str, list[str]],
             endpoints:dict,
             output_path:str,
             crawl_ports:Optional[Union[list[int],int]] = None,
             excl_ports:Optional[Union[int, list[int]]] = None
            ) -> dict:
        """
        This Method is designed to:
        1. scan a (number of) IP-Adress(es) for open ports
        2. identify the API-endpoints of the IoT-devices where apis are likely served
        3. crawl the API-endpoints of the identified ports on the given devices

        The endpoints should be specified as a dictionary looking like this:
        ```py
        endpoints = {
            "/api/v1/endpoint":{
                'num': 1,
                'method': 'GET',
                'expected_status_code': 200
            },
            "/api/v1/example":{
                'num': 2,
                'method': 'POST',
                'expected_status_code': 200
            }
        }
        ```
        :param ip_address: The IP-address, or list of IP-addresses to scan.
        :type ip_address: Union[str, list[str]]
        :param endpoints: The endpoints dict, containing the endpoints to crawl.
        :type endpoints: dict
        :param output_path: The path to save the output to.
        :type output_path: str
        :param crawl_ports: Optional argument, where you can specify port(s) that **MUST** be crawled. If you specify a port here, it will be crawled even if it is not open.
        :type crawl_ports: Union[list[int],int]
        :param excl_ports: Optional argument, where you can specify port(s) that **MUST NOT** be scanned. Because only open ports get crawled, this argument will also exclude ports from being crawled (if they aren't specified in the `crawl_ports` argument)
        :type excl_ports: Union[list[int],int]
        :return: a dict containing all the results of the scan
        """
        
        if crawl_ports == None:
            crawl_ports = []
        elif isinstance(crawl_ports, int):
            crawl_ports = [crawl_ports]
        elif not all(isinstance(port, int) for port in crawl_ports):
            raise TypeError(f"crawl_ports must be of type int or list[int]")
        
        if excl_ports == None:
            excl_ports = []
        elif isinstance(excl_ports, int):
            excl_ports = [excl_ports]
        elif not all(isinstance(port, int) for port in excl_ports):
            raise TypeError(f"excl_ports must be of type int or list[int]")
        
        port_scan_res = self._port_scan(ip_address=ip_address, excl_ports=excl_ports)
        
        for ip in port_scan_res.keys():
            ports = list(port_scan_res[ip].keys())
            ports.extend(crawl_ports)
            for port in ports:
                port_scan_res[ip][port]["endpoints"] = self._crawl_api(ip_address=ip, port=port, endpoints=endpoints, output_path=output_path)

        return port_scan_res