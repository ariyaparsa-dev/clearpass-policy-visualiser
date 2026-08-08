import yaml
from pyclearpass import *

def get_login():
    with open("config.yaml", "r") as f:
        cfg = yaml.safe_load(f)["clearpass"]

    return ClearPassAPILogin(
        server=cfg["server"],
        granttype=cfg["grant_type"],
        clientid=cfg["client_id"],
        clientsecret=cfg["client_secret"],
        verify_ssl=cfg["verify_ssl"]
    )