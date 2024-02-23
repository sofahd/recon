from configparser import ConfigParser
from utils.utils import load_var_from_config_and_validate
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
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

        self.log.info(f'Crawling API of {ip_address}:{port}', method="recon.ApiCrawler.crawl")
        ret_dict = {}

        ret_dict = self._request_endpoints(endpoints, ret_dict, ip_address, port, output_path) 

        return ret_dict
    
    def _request_endpoints(self, endpoints:dict, ret_dict:dict, ip_address:str, port:int, output_path:str) -> dict:
        """
        Request the endpoints from the IoT device.
        """
        
        ret_dict.update(endpoints)

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
                    self.log.error(f'Invalid method: {endpoint_dict["method"]} for url: {request_url}', method="recon.ApiCrawler._request_endpoints")
                    ret_dict.pop(endpoint, None)
                    continue
                
            except Exception as e:
                self.log.error(f'Exception: {e} for url: {request_url}', method="recon.ApiCrawler._request_endpoints")
                ret_dict.pop(endpoint, None)
                continue

            if response.status_code == endpoint_dict.get('expected_status_code') or response.status_code == endpoint_dict.get('status_code'):
                self.log.info(f'Valid response from {request_url}')
                
                with open(f"{output_path}/{ip_address}_{port}_{endpoint_dict['num']}.html", 'wb') as f:
                    f.write(response.content)

                further_endpoints = self._extract_further_endpoints(request_url, response.content)
                ret_dict[endpoint]['path'] = f"{output_path}/{ip_address}_{port}_{endpoint_dict['num']}.html"
                ret_dict[endpoint].pop('expected_status_code', None)
                ret_dict[endpoint]['status_code'] = response.status_code
                ret_dict[endpoint]['headers'] = dict(response.headers)
                if further_endpoints != []:
                    count = len(ret_dict.keys())
                    further_endpoints_dict = {}
                    for endpoint in further_endpoints:
                        if endpoint not in ret_dict.keys():
                            further_endpoints_dict[endpoint] = {
                                'num': count,
                                'method': 'GET',
                                'expected_status_code': 200
                            }
                            count += 1

                    self._request_endpoints(further_endpoints_dict, ret_dict, ip_address, port, output_path)



            else:
                self.log.error(f'Invalid response from {request_url}', method="recon.ApiCrawler._request_endpoints")
                ret_dict.pop(endpoint, None)
        
        return ret_dict
    
        
    def _extract_further_endpoints(self, base_url:str, response_content:bytes) -> list:
        """
        Extract links from HTML that are within the same domain as the base_url.

        ---
        :param base_url: The base URL to check the links against.
        :type base_url: str
        :param response_content: The response content to extract the links from.
        :type response_content: bytes
        :return: A set of unique URLs within the same domain as base_url.
        """


        soup = BeautifulSoup(response_content, 'html.parser')
        domain = urlparse(base_url).netloc
        urls = set()

        # Updated tag-attribute combinations to include images
        search_combinations = [
            ('a', 'href'),
            ('link', 'href'),  # For stylesheets and other link elements
            ('img', 'src'),    # For images
            ('script', 'src') # Add other combinations as needed, e.g., ('script', 'src') for scripts
        ]

        for tag, attribute in search_combinations:
            for element in soup.find_all(tag, attrs={attribute: True}):
                url = element[attribute]
                absolute_url = urljoin(base_url, url)  # Ensure the URL is absolute
                if urlparse(absolute_url).netloc == domain and "/" in url:
                    urls.add(url)

        return list(urls)
    

