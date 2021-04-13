import logging
import requests
from requests.auth import HTTPBasicAuth

class nsxProviderInstance():
    nsxEndpoint = None
    nsxUsername = None
    nsxPassword = None
    version = None
    tracer = None
    def __init__(self, nsxEndpoint, username, password, tracer: logging.Logger):
        self.nsxEndpoint = nsxEndpoint
        self.nsxUsername = username
        self.nsxPassword = password
        self.tracer = tracer

    def getNodeVersion(self):
        headers = dict()
        headers["Content-Type"] = "application/json"
        versionpath = "/api/v1/node/version"
        versionUrl = "https://" + self.nsxEndpoint + versionpath
        response = requests.get(versionUrl, headers=headers, auth=HTTPBasicAuth(self.nsxUsername, self.nsxPassword),
                                verify=False)
        return response.json()

    def getNodes(self):
        apiPath = "/api/v1/cluster/nodes"
        apiUrl = "https://" + self.nsxEndpoint+apiPath
        headers = dict()
        headers["Content-Type"] = "application/json"
        response = requests.get(apiUrl, headers=headers, auth=HTTPBasicAuth(self.nsxUsername, self.nsxPassword),
                            verify=False)
        # shrink node object
        nodeObj = dict()
        nodeobjArray = []
        for node in response.json()["results"]:
            nodeObj["display_name"] = node["display_name"]
            nodeObj["appliance_mgmt_listen_addr"] = node ["appliance_mgmt_listen_addr"]
            nodeobjArray.append(nodeObj)

        return nodeobjArray


    def getNodeNICs(self):
        apiPath = "/api/v1/node/network/interfaces"
        apiUrl = "https://"+self.nsxEndpoint+apiPath
        headers = dict()
        headers["Content-Type"] = "application/json"
        response = requests.get(apiUrl, headers=headers, auth=HTTPBasicAuth(self.nsxUsername, self.nsxPassword), verify=False)
        self.tracer.info(response.json())
        return response.json()

    def getAggregate(self, resource_type):
        apiPath = "policy/api/v1/search/aggregate"
        apiUrl = "https://"+self.nsxEndpoint+apiPath
        headers = dict()
        headers["Content-Type"] = "application/json"
        data = dict()
        data["primary"] = dict()
        data["primary"]["resource_type"] = resource_type
        response = requests.post(apiUrl, json=data, headers=headers, auth=HTTPBasicAuth(self.nsxUsername, self.nsxPassword), verify=False)
        return response.json()

    def getLogicalRouters(self):
        # will return gateways - tier0 , tier 1 etc
        apiPath = "/api/v1/logical-routers"
        apiUrl = "https://"+self.nsxEndpoint+apiPath
        headers = dict()
        headers["Content-Type"] = "application/json"
        response = requests.get(apiUrl, headers=headers, auth=HTTPBasicAuth(self.nsxUsername, self.nsxPassword), verify=False)

        routerObjArray = []
        for router in response.json()["results"]:
            routerObj = dict()
            routerObj["router_type"] = router["router_type"]
            routerObj["display_name"] = router["display_name"]
            #get consolidated status
            responseStatus = self.getAggregate(routerObj["router_type"])
            routerObj["OverAllStatus"] = responseStatus["consolidated_status"]
            routerObjArray.append(routerObj)
        self.tracer.info(response.json())
        return routerObjArray


