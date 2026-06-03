from configparser import ConfigParser
from typing import Optional, Union
import subprocess, os, time, select, json, tempfile
import xml.etree.ElementTree as ET
from sofahutils import load_var_from_config_and_validate, save_list_to_file
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

        # masscan/nmap scratch (input list + JSON/XML reports) is written here and removed
        # after parsing. It lives on a tmpfs so the container root FS can stay read-only.
        self._scratch_dir = tempfile.gettempdir()

    

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
            ports_to_delete = [port for port in masscan_res[ip] if port in excl_ports]
            for port in ports_to_delete:
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

        self.log.info(f"Starting the initial Masscan with {len(ip_address)} IP-addresses, while excluding {len(excl_ports)} ports.", method="recon.PortScan._masscan")
        
        input_file_path = os.path.join(self._scratch_dir, "masscan_input.txt")
        masscan_output_path = os.path.join(self._scratch_dir, "masscan_out.json")

        save_list_to_file(input_list=ip_address, filepath=input_file_path)

        command = ["masscan", "-iL", input_file_path, "-p", "0-65535", "-oJ", masscan_output_path, "--rate", self.rate]
        masscan = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        check_interval = 1

        try:
            while True:
                lines = self._masscan_read_subprocess_output(masscan.stderr)
                line = lines[-1] if lines else ""
                line = line.rstrip()
                if line != "":
                    self.log.info(f"Masscan: {line}", method="recon.PortScan._masscan")
                if (masscan.poll() is not None):
                    break
                if "waiting -" in line:
                    self.log.warn("Masscan is running endlessly, but we will kill it.", method="recon.PortScan._masscan")
                    masscan.kill()
                    break
                time.sleep(check_interval)
        finally:
            if masscan.returncode != 0 and masscan.returncode != -9:
                errormsg = f"Error with masscan, returncode: {masscan.returncode}, line: {line}"
                self.log.error(errormsg, method="recon.PortScan._masscan")
                raise MasscanFailedException(f"Masscan with input file: '{input_file_path}' failed! Error: {errormsg}")
            if masscan.returncode == -9:
                self.log.warn("Masscan was killed!", method="recon.PortScan._masscan")
            masscan.stdout.close()
            masscan.stderr.close()
       
        parsed_dict = self._parse_masscan_output(masscan_output_path=masscan_output_path)

        os.remove(input_file_path)
        os.remove(masscan_output_path)
        
        self.log.info("Initial Masscan ran successful!", method="recon.PortScan._masscan")

        return parsed_dict 
        
    def _masscan_read_subprocess_output(self, pipe)->list[str]:
        """
        Read the output from the masscan subprocess.
        :param pipe: The pipe to read from.
        :return: The output.
        """

        output = []
        while True:
            ready_to_read, _, _ = select.select([pipe], [], [], 0.1)
            if not ready_to_read:
                break
            line = pipe.readline()
            if not line:
                break
            output.append(line)
        return output

    
    def _parse_masscan_output(self, masscan_output_path:str)->dict:
        """
        Parse a masscan `-oJ` JSON report into ``{ip: {port: {"protocol", "timestamp"}}}``.

        masscan `-oJ` emits a JSON array of ``{"ip", "timestamp", "ports": [{"port", "proto",
        "status", ...}]}`` records (``proto`` is the transport, e.g. ``tcp``). Only ``open``
        ports are kept. ``port`` is an int key, matching what the rest of PortScan expects.

        :param masscan_output_path: The path to the masscan JSON output file.
        :type masscan_output_path: str
        :return: The parsed masscan output.
        :rtype: dict
        """

        with open(masscan_output_path, 'r') as f:
            records = self._load_masscan_json(f.read())

        out_dict = {}

        for record in records:
            ip = record.get("ip")
            if not ip:
                continue
            for port_entry in record.get("ports", []):
                status = port_entry.get("status")
                if status is not None and status != "open":
                    continue
                try:
                    port = int(port_entry["port"])
                except (KeyError, TypeError, ValueError):
                    continue
                out_dict.setdefault(ip, {})[port] = {
                    "protocol": port_entry.get("proto"),
                    "timestamp": record.get("timestamp"),
                }

        if out_dict == {}:
            self.log.warn("Masscan did not find any open ports!, This means probably something went wrong!", method="recon.PortScan._parse_masscan_output")
        return out_dict

    def _load_masscan_json(self, raw:str)->list:
        """
        Load masscan JSON output tolerantly.

        masscan usually emits valid JSON, but some builds leave a trailing comma before the
        closing bracket or omit the bracket entirely. Try a strict parse first, then fall
        back to parsing each ``{...}`` record line individually.

        :param raw: the raw file contents
        :type raw: str
        :return: a list of record dicts
        :rtype: list
        """

        raw = raw.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            records = []
            for line in raw.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{") and line.endswith("}"):
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return records
    

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
        
        self.log.info(f"Starting nmap scan on {ip_address}:{port}!", method="recon.PortScan._nmap")

        output_path = os.path.join(self._scratch_dir, "nmap_out.xml")

        nmap = subprocess.run(
            ["nmap", ip_address, "--script=banner", "-sV", "-p", str(port), "-oX", output_path],
            capture_output=True,
        )

        if nmap.returncode != 0:
            raise NmapFailedException(f"nmap with ip and port: '{ip_address}:{port}' failed! Error: {nmap.stderr}")

        ret_tuple = self._parse_nmap_xml(xml_path=output_path, port=port)

        os.remove(output_path)
        return ret_tuple

    def _parse_nmap_xml(self, xml_path:str, port:int)->tuple:
        """
        Parse an nmap `-oX` XML report for a single port into the (service_version, banner) tuple.

        ``service_version`` is nmap's service name, prefixed with the tunnel when present
        (e.g. ``ssl/http``), so downstream SSL detection (`"ssl" in service_version`) works.
        ``banner`` keeps the historical one-character mode prefix: ``b`` for a raw banner
        (``banner`` script) and ``h`` for an HTTP server header (``http-server-header`` script);
        ``_nmap_runner`` strips that prefix to set the port_spoof mode.

        :param xml_path: path to the nmap XML output file
        :type xml_path: str
        :param port: the port whose result should be extracted
        :type port: int
        :return: a tuple of (service_version, banner), either element may be None
        :rtype: tuple
        """

        service_version = None
        banner = None

        root = ET.parse(xml_path).getroot()

        for port_el in root.iter("port"):
            if port_el.get("portid") != str(port):
                continue

            service_el = port_el.find("service")
            if service_el is not None:
                name = service_el.get("name")
                tunnel = service_el.get("tunnel")
                if name:
                    service_version = f"{tunnel}/{name}" if tunnel else name

            for script_el in port_el.findall("script"):
                script_id = script_el.get("id")
                output = script_el.get("output", "").replace("\n", "")
                if script_id == "banner":
                    banner = "b" + output
                    break
                elif script_id == "http-server-header":
                    banner = "h" + output
                    break
            break

        return (service_version, banner)
    

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



                
