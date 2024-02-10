class MasscanFailedException(Exception):
    """
    Exception raised when Masscan fails.
    """
    pass

class NmapFailedException(Exception):
    """
    Exception raised when nmap fails.
    """
    pass


class WrongFileTypeException(Exception):
    """
    Exception raised when the file type is wrong.
    """
    pass

class InvalidConfigException(Exception):
    """
    Exception raised when the config is invalid.
    """
    pass

class PathIsNoFileException(Exception):
    """
    Exception raised when the path is no file.
    """
    pass
