import os, json, requests, time, random, datetime, subprocess
from typing import Optional, Union
from .exceptions import WrongFileTypeException,InvalidConfigException,PathIsNoFileException
from configparser import ConfigParser



def ip_to_digit(ip:str) -> int:
        """
        Take the last digit of the last part of the IP address
        :param ip: the IP-Adress
        :type ip: str
        :return: int with the last digit, -1 if something went wrong
        """
        
        try:
                ret_int = int(ip[-1])
        except:
                ret_int = -1

        return ret_int


def get_own_ip(config:ConfigParser, logger = None) -> Optional[str]:
        """
        This function makes a http request to one of a few apis to get the own ip.
        :param config: expects a config to get the urls
        :type config: ConfigParser
        :param logger: The Logger object to allow this helper function to work with logging aswell.
        :type Logger: JsonLogger
        :return: str of ip if sucessfull, `127.0.0.1` if not
        """
        
        ret_value = "127.0.0.1"

        api_list = json.loads(load_var_from_config_and_validate(config=config, section='Utils', option='api_list'))

        for url in api_list:
                try: 
                        response = requests.get(url,timeout=5)
                        response.raise_for_status()
                        ret_value = response.text
                        break
                except Exception as e:
                        if logger != None:
                                logger.warn(f"Could not reach endpoint: {url} because Error {str(e)}", 'honeypot_utils.get_own_ip')
                        pass
        return ret_value


def load_config(path:str) -> ConfigParser:
        """
        Function to load a file as a config
        :param path: the path to the config
        :type path: str
        :return: a configparser Object with a loaded config
        """
        
        validate_path_and_extension(path=path, extension=".ini")
        
        config = ConfigParser()
        config.read(path)
        return config

def validate_path_and_extension(path:str, extension:str):
        """
        This function can be used to validate a filepath
        If no exceptions were thrown, the filepath is ok.
        :param path: the filepath you want to verify
        :type path: str
        :param extension: the File extension you expect the path to have either with `.` at the beginning or not.
        :type extension: str
        """
        if not extension[0] == '.':
                extension = '.' + extension

        if not os.path.isfile(path=path):
                raise PathIsNoFileException(f"The path `{path}` is not pointing to a file!")
        
        if not os.path.splitext(path)[1] == extension:
                raise WrongFileTypeException(f"The supplied filepath: {path} does not point to a `{extension}` file!")


def load_json_file_to_dict(path:str)->Union[dict, list]:
        """
        Function to return a dict from a provided json file.
        :param path: The filepath to the file that contains the dict
        :type path: str
        :return: the loaded dict, or list
        """

        validate_path_and_extension(path=path, extension='.json')

        with open(path) as file:
                return json.loads(file.read())


def repair_folder_path(path:str)->str:
        """
        Function that makes sure a folder path is omitted with a `/`
        :param path: folder path
        :type path: str
        :return: a string with a repaired path
        """

        if path[-1] != '/':
                path = path + '/'

        return path

def validate_config(config:ConfigParser, section:str, option:str):
        """
        This function is used to validate a config, if the option in the section is not existent, a InvalidConfigException gets thrown.
        :param config: The config that has to get validated
        :type config: ConfigParser Object
        :param section: the section you expect the `option` to be in.
        :type section: str
        :param option: the option you want to retrieve
        :type option: str
        """

        if not config.has_option(section, option):
            raise InvalidConfigException(f"The config does not feature a `{option}` option under the `{section}`-Section!")
        

def load_var_from_config_and_validate(config:ConfigParser, section:str, option:str):
        """
        This function is used to load a var from a config, however before loading the config gets validated.
        If the option in the section is not existent, a InvalidConfigException gets thrown.
        :param config: The config that has to get validated
        :type config: ConfigParser Object
        :param section: the section you expect the `option` to be in.
        :type section: str
        :param option: the option you want to retrieve
        :type option: str
        :return: Whatever was in the config
        """

        validate_config(config,section,option)
        return config[section][option]

def create_ip_db_port_persistence(config:ConfigParser, ip:str, port:str):
        """
        This function is built to implement persistence for the relationship between dropbear ports and source IP-adresses.
        Also a timestamp is logged.
        :param config: The config for filepaths
        :type config: ConfigParser Object
        :param ip: the IP-Adress, you want to create persistence for.
        :type ip: str
        :param port: the port for the persistence
        :type port: str
        """
        
        file_path = load_var_from_config_and_validate(config=config, section="Paths", option="ip_persistence_path")
        ip_dict = load_json_file_to_dict(file_path)

        ip_dict[ip] = {
                "port": port,
                "time": round(time.time())
        }

        ip_dict = clean_ip_dict(input_dict=ip_dict)

        save_as_json(path=file_path, content=ip_dict)

def get_port_for_db_ip_adress(config:ConfigParser, ip:str)->Optional[str]:
        """
        Function to get the port of a specified IP-Adress, or none if the ip-entry does not exist yet.
        :param config: The config for filepaths
        :type config: ConfigParser Object
        :param ip: the IP-Adress, you want to create persistence for.
        :type ip: str
        """
        
        retval = None

        file_path = load_var_from_config_and_validate(config=config, section="Paths", option="ip_persistence_path")
        try:
                ip_dict = load_json_file_to_dict(file_path)
        except PathIsNoFileException:
                ip_dict={}
        ip_dict = clean_ip_dict(input_dict=ip_dict)
        
        if ip in ip_dict.keys():
                ip_dict[ip]['time'] = round(time.time())
                retval = ip_dict[ip]['port']

        save_as_json(path=file_path, content=ip_dict)
        return retval

def clean_ip_dict(input_dict:dict)->dict:
        """
        Function to remove every ip, that hasn't been accessed for longer than 24 h
        :param input_dict: the dict we want to clean up
        :type input_dict: dict
        :return: the cleaned up dict
        """
        
        now = round(time.time())
        del_list = []

        for iteration_ip in input_dict.keys():
                if (now - input_dict[iteration_ip]['time']) > 86400:
                        del_list.append(iteration_ip)

        for iteration_ip in del_list:
                input_dict.pop(iteration_ip)        

        return input_dict

def save_as_json(path:str, content:dict, mode:Optional[str]='w', newline:Optional[bool] = False):
        """
        Function that saves json serializable objects to json file with given path.
        :param path: The path to the file
        :type path: str
        :param content: the content to be saved
        :type content: dict
        :param mode: The mode, if you want to change it from the default (`w`)
        :type mode: Optional[str]
        :param newline: decide whether you need to add a newline after each writing operation Optional, default: `False` useful, if you want to use `mode='a'`
        :type newline: Optional[str]
        """

        with open(path, mode) as outfile:
            json.dump(content, outfile)
            if newline:
                outfile.write("\n")


def get_random_realistic_time()->str:
        """
        Helper-Function to just return a time and date value that is in the last few years.
        :return: string with the time
        """

        timestamp = random.randint(1612259945,int(time.time()))

        return format_unix_timestamp_to_html(timestamp)



def format_unix_timestamp_to_html(unix_timestamp:int)->str:
        """
        This helper function can format a unix timestamp to a string looking like this: ´Tue, 17 Jan 2023 09:06:24 GMT´
        :param unix_timestamp: The unix timestamp
        :type unix_timestamp: int
        :return: the formatted string
        """
        
        dt_object = datetime.datetime.fromtimestamp(unix_timestamp)

        return dt_object.strftime('%a, %d %b %Y %H:%M:%S GMT')


def get_timestamp_now()->str:
        """
        helper function that returns a formatted timestamp of now.
        looking similiar to this: ´Tue, 17 Jan 2023 09:06:24 GMT´
        :return: string with the appropriate timestamp.
        """
        return format_unix_timestamp_to_html(round(time.time()))


def execute_wget_command(url:str, filename:str, path:str, json_logger, ip:str, port:int):
        """
        function, that executes a wget command, for a url and with a filename.
        :param url: The URL where the file for the wget is hosted
        :type url: str
        :param filename: The filename of the file
        :type filename: str
        :param path: the path where the file should be saved
        :type path: str
        :param json_logger: the logger
        :type json_logger: JsonLogger
        :param ip: the source IP-Adress
        :type ip: str
        :param port: the source port
        :type port: int
        """

        filename = filename.split("/")[-1]
        file_ext = f".{filename.split('.')[-1]}"
        filename = filename.replace(file_ext, '')
        final_path = f"{path}/{filename}-{str(int(time.time()))}{file_ext}"
        command = f"wget {url} -O {final_path}"
         
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        logging_dict = {
                "wget_response": str(result.stdout),
                "file": final_path,
                "wget_url:": url
        }

        json_logger.log(eventid="honeypot_utils.execute_wget_command.downloaded_wget", content=logging_dict, ip=ip, port=port)
        if result.returncode!=0:
                json_logger.error(f"Command: '{command}' returned non-zero exit status {result.returncode}. Output: {result.stderr}", "execute_wget_command")


def save_list_to_file(input_list:list[str], filepath:str):
        """
        Used to save a list of strings linewise to a file.
        :param input_list: the list of strings
        :type input_list: list[str]
        :param filepath: the filepath
        :type filepath: str
        """

        with open(filepath, 'w') as file:
                for line in input_list:
                        file.write(f"{line}\n")

def remove_multiple_substrings_from_string(input_string:str, substrings:list[str])->str:
        """
        This function removes multiple substrings from a string.
        :param input_string: the string you want to remove substrings from
        :type input_string: str
        :param substrings: the substrings you want to remove
        :type substrings: list[str]
        :return: the string without the substrings
        :rtype: str
        """
        
        for substring in substrings:
                input_string = input_string.replace(substring, '')

        return input_string
        