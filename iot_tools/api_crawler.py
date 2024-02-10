from configparser import ConfigParser
from recon.utils.utils import load_var_from_config_and_validate
import requests, copy

class ApiCrawler:

    """
    This class is designed to be used as a crawler for the API of an IoT device.
    """

    def __init__(self, logger, config:ConfigParser) -> None:
        """
        Constructor for ApiCrawler class.
        """
        
        self.log = logger
        self.config = config
        

    def crawl(self, ip_address:str, port:int, endpoints:dict, output_path:str) -> dict:
        """
        Crawl the API of an IoT device.

        The endpoints should be specified as a dictionary looking like this:
        ```py
        endpoints = {
            "/api/v1/endpoint":{
                'num': 1,
                'method': 'GET',
                'data': {'key': 'value'},
                'expected_status_code': 200
            },
            "/api/v1/example":{
                'num': 2,
                'method': 'POST',
                'data': None,
                'expected_status_code': 200
            }
        }
        ```
        :param ip_address: The IP-address of the IoT device.
        :type ip_address: str
        :param port: The port of the IoT device.
        :type port: int
        :param endpoints: The endpoints dict, containing the endpoints to crawl.
        :type endpoints: dict
        :param output_path: The path to save the output to.
        :type output_path: str
        :return: dict, containing the crawled endpoints.
        """

        self.log.info(f'Crawling API of {ip_address}:{port}')
        ret_dict = copy.deepcopy(endpoints)

        for endpoint in endpoints.keys():
            
            endpoint_dict = endpoints[endpoint]
            request_url = f'http://{ip_address}:{port}{endpoint}'
            
            data = endpoint_dict.get('data')

            try:    
                if endpoint_dict["method"] == 'GET':
                    response = requests.get(
                        url=request_url,
                        data=data
                    )

                elif endpoint_dict['method'] == 'POST':
                    response = requests.post(
                        url=request_url,
                        data=data
                    )

                else:
                    self.log.error(f'Invalid method: {endpoint_dict["method"]} for url: {request_url}')
                    ret_dict.pop(endpoint, None)
                    continue
                
            except Exception as e:
                self.log.error(f'Exception: {e} for url: {request_url}')
                ret_dict.pop(endpoint, None)
                continue

            if response.status_code == endpoint_dict['expected_status_code']:
                self.log.info(f'Valid response from {request_url}')
                
                with open(f"{output_path}/{ip_address}_{port}_{endpoint_dict['num']}.html", 'wb') as f:
                    f.write(response.content)

                ret_dict[endpoint]['path'] = f"{output_path}/{ip_address}_{port}_{endpoint_dict['num']}.html"
                ret_dict[endpoint].pop('expected_status_code', None)
                ret_dict[endpoint]['status_code'] = response.status_code
                ret_dict[endpoint]['headers'] = response.headers

            else:
                self.log.error(f'Invalid response from {request_url}')
                ret_dict.pop(endpoint, None)

        return ret_dict
    
        
        

