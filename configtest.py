import configparser
import json

if __name__ == "__main__":
    configfile = 'config'
    config_obj = configparser.ConfigParser()
    config_obj.read(configfile)
    print(type(json.loads(config_obj.get('db', 'mapping'))))
