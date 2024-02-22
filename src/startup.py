from iot_recon import IotRecon
from iot_tools.api_crawler import ApiCrawler
import json

def main():
    recon = IotRecon(path="/home/pro/data/config.ini")
    endpoints = {
        "/":{
            'num': 1,
            'method': 'GET',
            'expected_status_code': 200
        },
        "/get":{
            'num': 2,
            'method': 'GET',
            'expected_status_code': 200
        },
        "/get_pm10":{
            'num': 3,
            'method': 'GET',
            'expected_status_code': 200
        },
        "/get_pm25":{
            'num': 4,
            'method': 'GET',
            'expected_status_code': 200
        }
    }
    t = recon.scan(ip_address=["89.163.151.200","79.249.154.227"], endpoints=endpoints, output_path="/home/pro/data")
    print(json.dumps(t, indent=4))

    

if __name__ == '__main__':
    main()

