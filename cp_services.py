from pyclearpass import *
from cp_client import get_login

def get_all_services():

    login = get_login()

    result = ApiPolicyElements.get_config_service(
        login,
        limit=1000
    )

    return result.get("_embedded", {}).get("items", [])


def get_service(service_id):

    login = get_login()

    return ApiPolicyElements.get_config_service_by_services_id(
        login,
        services_id=str(service_id)
    )