import json
import requests

from requests.auth import HTTPBasicAuth
from .base import ProviderInstance, ProviderCheck

class hcxProviderInstance():
    hcxEndpoint= None
    authToken = None
    vcGUID = None
    serviceMeshId = None
    def __init__(self, hcxEndpoint: str, userName: str, passWord: str ):
        self.hcxEndpoint = hcxEndpoint

        # Get authtoken for the session
        sessionAPIPath = "/hybridity/api/sessions"
        sessionurl = "https://" + hcxEndpoint + sessionAPIPath
        requestBody = dict()
        requestBody["username"] = userName
        requestBody["password"] = passWord
        headers = {'accept':'application/json', 'Accept':'application/json', 'Content-Type':'application/json'}
        response = requests.post(sessionurl, json=requestBody, headers=headers, verify=False)
        self.authToken = response.headers['x-hm-authorization']

        # Get VC GUid for the session
        vcGUIDIPath = "/hybridity/api/metainfo/context/interconnect"
        vcGUIDURL = "https://" + vcGUIDIPath + vcGUIDIPath
        # add session token
        headers['x-hm-authorization'] = self.authToken
        response = requests.get(vcGUIDURL,headers=headers)
        vcguidbody = response.json()
        self.vcGUID = vcguidbody[0] if len(vcguidbody)>0  else None
        if self.vcGUID == None:
            print("vcguid not found!!!!!!")
            return


    def getMetainfo(self):
        metapath = "/hybridity/api/metainfo/context/publisher"
        metaUrl = "https://" + self.hcxEndpoint + metapath
        headers = {'accept': 'application/json', 'Accept': 'application/json', 'Content-Type': 'application/json'}
        headers['x-hm-authorization'] = self.authToken
        response = requests.get(metaUrl, headers=headers)
        return response.json()

    def getServiceMesh(self):
        serviceMeshpath = "/hybridity/api/metainfo/context/publisher"
        serviceMeshUrl = "https://" + self.hcxEndpoint + serviceMeshpath
        headers = {'accept': 'application/json', 'Accept': 'application/json', 'Content-Type': 'application/json'}
        headers['x-hm-authorization'] = self.authToken
        response = requests.get(serviceMeshUrl, headers=headers)
        self.serviceMeshId = response.json()[0]["serviceMeshId"]
        return response.json()

    def getApppliances(self):
        appliancePath = "/hybridity/api/interconnect/appliances/query?vcGuid="
        applianceUrl = "https://" + appliancePath + self.vcGUID
        headers = {'accept': 'application/json', 'Accept': 'application/json', 'Content-Type': 'application/json'}
        headers['x-hm-authorization'] = self.authToken
        requestBody = dict()
        requestBody["filter"] = dict()
        requestBody["filter"]["serviceMeshId"] = self.serviceMeshId
        response = requests.post(applianceUrl, json=requestBody, headers=headers)
        return response.json()






