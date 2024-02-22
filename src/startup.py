from iot_recon import IotRecon
import os

def main():
    recon = IotRecon(path="/home/pro/data/config.ini", log_url=os.getenv("LOG_API"))
    recon.scan_from_config()

    

if __name__ == '__main__':
    main()

