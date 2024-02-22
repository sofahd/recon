from iot_recon import IotRecon

def main():
    recon = IotRecon(path="/home/pro/data/config.ini")
    recon.scan_from_config()

    

if __name__ == '__main__':
    main()

