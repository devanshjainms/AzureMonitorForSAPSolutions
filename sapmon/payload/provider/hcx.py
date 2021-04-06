import json
import requests

from requests.auth import HTTPBasicAuth
from .base import ProviderInstance, ProviderCheck


class hcxProviderInstance():
    hcxEndpoint = None
    authToken = None
    vcGUID = None
    serviceMeshArray = []

    def __init__(self, hcxEndpoint: str, userName: str, passWord: str):
        self.hcxEndpoint = hcxEndpoint

        # Get authtoken for the session
        sessionAPIPath = "/hybridity/api/sessions"
        sessionurl = "https://" + hcxEndpoint + sessionAPIPath
        requestBody = dict()
        requestBody["username"] = userName
        requestBody["password"] = passWord
        headers = {'accept': 'application/json', 'Accept': 'application/json', 'Content-Type': 'application/json'}
        response = requests.post(sessionurl, json=requestBody, headers=headers, verify=False)
        self.authToken = response.headers['x-hm-authorization']

        # Get VC GUid for the session
        vcGUIDIPath = "/hybridity/api/metainfo/context/interconnect"
        vcGUIDURL = "https://" + self.hcxEndpoint + vcGUIDIPath
        # add session token
        headers['x-hm-authorization'] = self.authToken
        response = requests.get(vcGUIDURL, headers=headers, verify=False)
        vcguidbody = response.json()
        self.vcGUID = vcguidbody[0] if len(vcguidbody) > 0 else None
        if self.vcGUID == None:
            print("vcguid not found!!!!!!")
            return

    def getMetainfo(self):
        metapath = "/hybridity/api/metainfo/context/publisher"
        metaUrl = "https://" + self.hcxEndpoint + metapath
        headers = {'accept': 'application/json', 'Accept': 'application/json', 'Content-Type': 'application/json'}
        headers['x-hm-authorization'] = self.authToken
        response = requests.get(metaUrl, headers=headers, verify=False)
        return response.json()

    # return serviceMeshArray
    def getServiceMesh(self):
        serviceMeshpath = "/hybridity/api/metainfo/context/publisher"
        serviceMeshUrl = "https://" + self.hcxEndpoint + serviceMeshpath
        headers = {'accept': 'application/json', 'Accept': 'application/json', 'Content-Type': 'application/json'}
        headers['x-hm-authorization'] = self.authToken
        response = requests.get(serviceMeshUrl, headers=headers, verify=False)
        for serViceMesh in response.json()["items"]:
            serviceMeshObj = dict()
            serviceMeshObj["serviceMeshId"] = serViceMesh["serviceMeshId"]
            serviceMeshObj["status"] = serViceMesh["status"]
            self.serviceMeshArray.append(serviceMeshObj)
        return self.serviceMeshArray

    # returns appliance array
    def getApppliances(self):
        allAppliances = []
        appliancePath = "/hybridity/api/interconnect/appliances/query?vcGuid="
        applianceUrl = "https://" + appliancePath + self.vcGUID
        headers = {'accept': 'application/json', 'Accept': 'application/json', 'Content-Type': 'application/json'}
        headers['x-hm-authorization'] = self.authToken
        requestBody = dict()
        requestBody["filter"] = dict()
        for serviceMesh in self.serviceMeshArray:
            requestBody["filter"]["serviceMeshId"] = serviceMesh["serviceMeshId"]
            response = requests.post(applianceUrl, json=requestBody, headers=headers, verify=False)
            for appliance in response.json()["items"]:
                appliance.pop("peerAppliances", None)
                # picking the necessary fields here
                applianceObj = dict()
                applianceObj["name"] = appliance["applianceName"]
                applianceObj["type"] = appliance["applianceType"]
                applianceObj["computeProfileId"] = appliance["computeProfileId"]
                applianceObj["serviceMeshId"] = serviceMesh["serviceMeshId"]
                applianceVersion = appliance["applianceVersion"]["major"] + '.' \
                                   + appliance["applianceVersion"]["minor"] + '.' \
                                   + appliance["applianceVersion"]["patch"] + '.' \
                                   + appliance["applianceVersion"]["build"]
                applianceObj["applianceVersion"] = applianceVersion
                if appliance["status"] and appliance["status"]["summary"]:
                    applianceObj["overallStatus"] = appliance["overallStatus"]
                    applianceObj["reasons"] = appliance["reasons"]
                allAppliances.append(applianceObj)
        return allAppliances
