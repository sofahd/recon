from configparser import ConfigParser
from typing import Optional, Union
import subprocess, os
from utils.utils import load_var_from_config_and_validate, save_list_to_file, remove_multiple_substrings_from_string
from utils.exceptions import MasscanFailedException, NmapFailedException



class PortScan:
    """
    Class used to scan for open ports on an IP-address.
    
    """

    def __init__(self, config:ConfigParser, logger):
        """
        Constructor for PortScan class.
        :param config: The config.
        :type config: ConfigParser
        """
        self.log = logger
        self.config = config

        self.rate = load_var_from_config_and_validate(config=config, section='Masscan', option='rate')

    

    def scan(self, ip_address:Union[str, list[str]], excl_ports:list[int]) -> dict:
        """
        Scan one or many IP-addresses. If you know ports to be excluded, you can specify them in the `excl_ports`.

        :param ip_address: The IP-address, or list of IP-addresses to scan.
        :type ip_address: Union[str, list[str]]
        :param excl_ports: The ports to exclude from the scan.
        :type excl_ports: list[int]
        :return: A dict containing the scan results.
        """

        ip_address = [ip_address] if type(ip_address) == str else ip_address

        if not isinstance(ip_address, list) or not all(isinstance(item, str) for item in ip_address):
            raise TypeError(f"ip_address must be of type str or list[str], not {type(ip_address)}")
        if not isinstance(excl_ports, list) or not all(isinstance(item, int) for item in excl_ports):
            raise TypeError(f"excl_ports must be of type int or list[int], not {type(excl_ports)}")
        
        masscan_res = self._masscan(ip_address=ip_address, excl_ports=excl_ports)

        for ip in masscan_res.keys():
            for port in masscan_res[ip].keys():
                if port in excl_ports:
                    del masscan_res[ip][port]
        
        nmap_res = self._nmap_runner(dict_to_scan=masscan_res)

        return nmap_res


    def _masscan(self, ip_address:list[str], excl_ports:list[int])->dict:
        """
        Scan the list of Ip-addresses with masscan, exclude the ports in excl_ports.

        :param ip_address: The IP-addresses to scan.
        :type ip_address: list[str]
        :param excl_ports: The ports to exclude from the scan.
        :type excl_ports: list[int]
        :return: a parsed dict with all gathered information
        """

        self.log.info(f"Starting the initial Masscan with {len(ip_address)} IP-addresses, while excluding {len(excl_ports)} ports.")
        
        input_file_path = os.getcwd() + "/masscan_input.txt"
        masscan_output_path = os.getcwd() + "/masscan_out.txt"

        save_list_to_file(input_list=ip_address, filepath=input_file_path)
        ## TODO: Adjust the ports to scan
        masscan = subprocess.run(f"masscan -iL {input_file_path} -p 80,8080,443,22,21,49123,53301 -oG {masscan_output_path} --rate {self.rate}",shell=True, capture_output=True)
        
        if masscan.returncode != 0:
            raise MasscanFailedException(f"Masscan with input file: '{input_file_path}' failed! Error: {masscan.stderr}")
        
        parsed_dict = self._parse_masscan_output(masscan_output_path=masscan_output_path)

        os.remove(input_file_path)
        os.remove(masscan_output_path)
        
        self.log.info("Initial Masscan ran successful!")

        return parsed_dict 
        
    
    def _parse_masscan_output(self, masscan_output_path:str)->dict:
        """
        Parse the masscan output file.

        :param masscan_output_path: The path to the masscan output file.
        :type masscan_output_path: str
        :return: The parsed masscan output.
        :rtype: dict
        """
        
        with open(masscan_output_path, 'r') as f:
            lines = f.readlines()

        out_dict = {}
            
        for line in lines:
            if not line.startswith('#') and not line.startswith('\n') and line.startswith("Timestamp: "):
                tabs = line.split('\t')
                timestamp = remove_multiple_substrings_from_string(input_string=tabs[0], substrings=["Timestamp: ", "\n", " "])
                ip = remove_multiple_substrings_from_string(input_string=tabs[1], substrings=["Host: ", "\n", " ", "(", ")"])
                port_and_proto = remove_multiple_substrings_from_string(input_string=tabs[2], substrings=["Ports: ", "\n", " "]).split('/', 1)
                port = int(port_and_proto[0])
                protocol = remove_multiple_substrings_from_string(input_string=port_and_proto[1], substrings=["\n", " ", "open/tcp", "open/udp", "//"])
                
                if ip not in out_dict.keys():   
                    out_dict[ip] = {port: {"protocol": protocol, "timestamp": timestamp}}
                else:
                    out_dict[ip][port] = {"protocol": protocol, "timestamp": timestamp}

        return out_dict
    

    def _nmap(self, ip_address:str, port:int)->tuple:
        """
        Scan ONE IP-address/port combination with nmap.
        This is mainly used to get the service version and banner.

        :param ip_address: The IP-address to scan.
        :type ip_address: str
        :param ports: The ports to scan.
        :type ports: int
        :return: A tuple of serviceversion and banner.
        :rtype: tuple
        """
        
        ret_tuple = (None, None)

        self.log.info(f"Starting nmap scan on {ip_address}:{port}!")

        nmap = subprocess.run(f"nmap {ip_address} --script=banner -sV -p {port} -oN {os.getcwd()}/nmap_out.txt", shell=True, capture_output=True)
       
        if nmap.returncode != 0:
            raise NmapFailedException(f"Masscan with ip and port: '{ip_address}:{port}' failed! Error: {nmap.stderr}")
        with open(os.getcwd() + "/nmap_out.txt", 'r') as f:
            lines = f.readlines()
        
        service_version = banner = None
        
        for line in lines: 
            
            if line.startswith(str(port)) and "open" in line:
                service_version = line.split(' ')[3]
            
            if line.startswith("|_banner: "):
                banner = "b" + line.removeprefix("|_banner: ").replace("\n", "")
                
            
            elif line.startswith("|_http-server-header: "):
                banner = "h" + line.removeprefix("|_http-server-header: ").replace("\n", "")

            if service_version != None and banner != None:
                ret_tuple = (service_version, banner)
                break
        
        os.remove(os.getcwd() + "/nmap_out.txt")
        return ret_tuple
    

    def _nmap_runner(self, dict_to_scan:dict)->dict:
        """
        Run nmap on the dict_to_scan.

        the dict should have the following structure:
        ```json
        {
            "<ip>": {
                "<port>": {
                    "protocol": "https",
                    "timestamp": "1705530003"
                },
                "80": {
                    "protocol": "http",
                    "timestamp": "1705530003"
                }
            },
            "127.0.0.1": {
                "8080": {
                    "protocol": "http-alt",
                    "timestamp": "1705530003"
                }
            }
        }
        ```

        :param dict_to_scan: The dict to scan.
        :type dict_to_scan: dict
        :return: The parsed nmap output.
        :rtype: dict
        """
        
        for ip in dict_to_scan.keys():
            for port in dict_to_scan[ip].keys():
                service_version, banner = self._nmap(ip_address=ip, port=port)
                if banner != None:
                    mode = banner[0]
                    banner = banner[1:]
                    if mode == "b":
                        dict_to_scan[ip][port]["mode"] = "banner"
                    elif mode == "h":
                        dict_to_scan[ip][port]["mode"] = "http-header"
                dict_to_scan[ip][port]["service_version"] = service_version
                dict_to_scan[ip][port]["banner"] = banner
                
        return dict_to_scan



                
