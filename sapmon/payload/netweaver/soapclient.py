# Python modules
import json
import logging
from datetime import datetime, timedelta, timezone
from time import time
from typing import Any, Callable
import re
import requests
from requests import Session
from threading import Lock

# SOAP Client modules
from zeep import Client
from zeep import helpers
from zeep.transports import Transport
from zeep.exceptions import Fault

# Payload modules
from helper.tools import *
from netweaver.metricclientfactory import NetWeaverSoapClientBase

# Suppress SSLError warning due to missing SAP server certificate
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# timeout to use for all SOAP WSDL fetch and other API calls
SOAP_API_TIMEOUT_SECS = 5

########
# implementation for the NetWeaverSoapClientBase abstract class.
# concrete implementation that initializes a SOAP client based on a WSDL URL to the same instance.
########
class NetWeaverSoapClient(NetWeaverSoapClientBase):

    def __init__(self,
                 tracer: logging.Logger,
                 logTag: str,
                 sapSid: str, 
                 sapHostName: str,
                 sapSubdomain: str,
                 httpProtocol: str,
                 httpPort: int):

        if not sapHostName or not httpProtocol or not httpPort:
            raise Exception("%s cannot create client with empty SID, hostname, httpProtocol, or port (%s|%s|%s|%s)" % \
                            (logTag, sapSid, sapHostName, httpProtocol, httpPort))

        httpProtocol = httpProtocol.lower()

        if httpProtocol != "http" and httpProtocol != "https":
            raise Exception("%s httpProtocol %s is not valid for hostname: %s, port: %s" % \
                            (logTag, httpProtocol, sapHostName, httpPort))

        self.tracer = tracer
        self.sapSid = sapSid
        self.wsdlUrl = NetWeaverSoapClient._getFullyQualifiedWsdl(sapHostName, sapSubdomain, httpProtocol, httpPort)

        # fetch WSDL URL to initialize internal SOAP API client
        self.client = self._initSoapClient(logTag=logTag)

    #####
    # public property getter methods
    #####

    """
    fully qualified WSDL url that was used to initialize this SOAP client
    """
    @property
    def Wsdl(self) -> str:
        return self.wsdlUrl

    ##########
    # public methods for NetWeaverSoapClientBase abstract base class interface
    ##########
    
    """
    invoke GetSystemInstanceList SOAP API - returns list of metadata for all server instances in SAP system, 
    including availability status and supported features/functions
    """
    def getSystemInstanceList(self, logTag: str) -> list:
        apiName = 'GetSystemInstanceList'
        result = self._callSoapApi(apiName, logTag)
        return NetWeaverSoapClient._parseResults(result)

    """
    invoke GetProcessList SOAP API - metrics for availability of SAP services running on all machines in SAP system
    applies to all instances within SAP system
    """
    def getProcessList(self, logTag: str) -> list:
        apiName = 'GetProcessList'
        result = self._callSoapApi(apiName, logTag)
        return NetWeaverSoapClient._parseResults(result)

    """
    invoke ABAPGetWPTable SOAP API - metrics for active ABAP worker processes
    applies to hosts with features:  ABAP
    """
    def getAbapWorkerProcessTable(self, logTag: str) -> list:
        apiName = 'ABAPGetWPTable'
        result = self._callSoapApi(apiName, logTag)
        return NetWeaverSoapClient._parseResults(result)

    """
    invoke GetQueueStatistic SOAP API - metrics for application server worker process queues
    applies to hosts with features:  ABAP, J2EE, JEE
    """
    def getQueueStatistic(self, logTag: str) -> list:
        apiName = 'GetQueueStatistic'
        result = self._callSoapApi(apiName, logTag)
        return NetWeaverSoapClient._parseResults(result)

    """
    invoke EnqGetStatistic SOAP API - metrics from ENQUE server around enqueue lock statistics
    applies to hosts with features:  ENQUE
    """
    def getEnqueueServerStatistic(self, logTag: str) -> list:
        apiName = 'EnqGetStatistic'
        result = self._callSoapApi(apiName, logTag)
        return NetWeaverSoapClient._parseResult(result)

    """
    invoke GetEnvironment SOAP API - host details from SAP instance
    used for mapping all hosts with azure resource id
    """
    def getEnvironment(self, logTag: str) -> list:
        apiName = 'GetEnvironment'
        result = self._callSoapApi(apiName, logTag)
        return NetWeaverSoapClient._parseResults(result)

    ##########
    # private static helper methods
    ##########
    """
    create fully qualified domain name of format {hostname}[.{subdomain}]
    """
    @staticmethod
    def _getFullyQualifiedDomainName(hostname: str, subdomain: str) -> str:
        if subdomain:
            return hostname + "." + subdomain
        else:
            return hostname

    """
    create SOAP WSDL url with fully qualified domain name and the specified protocol+port
    """
    @staticmethod
    def _getFullyQualifiedWsdl(hostname: str, 
                               subdomain: str, 
                               httpProtocol: str, 
                               httpPort: int) -> str:
        fqdn = NetWeaverSoapClient._getFullyQualifiedDomainName(hostname, subdomain).lower()
        return '%s://%s:%d/?wsdl' % (httpProtocol, fqdn, httpPort)

    """
    per SAP documentation, return default HTTP port of form 5XX13, where XX is the SAP Instance Number
    """
    @staticmethod
    def _getHttpPortFromInstanceNr(instanceNr: str) -> str:
        return '5%s13' % str(instanceNr).zfill(2)

    """
    per SAP documentation, return default HTTPS port of form 5XX14, where XX is the SAP Instance Number
    """
    @staticmethod
    def _getHttpsPortFromInstanceNr(instanceNr: str) -> str:
        return '5%s14' % str(instanceNr).zfill(2)

    """
    helper method to deserialize a LIST of zeep SOAP API results and return as list of python dictionary objects
    """
    @staticmethod
    def _parseResults(results: list) -> list:
        return helpers.serialize_object(results, dict)

    """
    helper method to deserialize a SINGLE zeep SOAP API result and return as single-element list of python dictionary objects
    """
    @staticmethod
    def _parseResult(result: object) -> list:
        return [helpers.serialize_object(result, dict)]

    ##########
    # private member methods
    ##########

    """
    private method to initialize internal SOAP API client and return the initialized client object, or throw if initialization fails
    """
    def _initSoapClient(self, logTag: str) -> Client:
        self.tracer.info("%s begin initialize SOAP client for wsdl: %s", logTag, self.wsdlUrl)

        startTime = time()
        client = None
        try:
            session = Session()
            session.verify = False
            client = Client(self.wsdlUrl, transport=Transport(session=session, timeout=SOAP_API_TIMEOUT_SECS, operation_timeout=SOAP_API_TIMEOUT_SECS))
            self.tracer.info("%s initialize SOAP client SUCCESS for wsdl: %s [%d ms]",
                             logTag, self.wsdlUrl, TimeUtils.getElapsedMilliseconds(startTime))
            return client
        except Exception as e:
            self.tracer.error("%s initialize SOAP client ERROR for wsdl: %s [%d ms] %s",
                              logTag, self.wsdlUrl, TimeUtils.getElapsedMilliseconds(startTime), e, exc_info=True)
            raise e

    """
    reflect against internal SOAP API client and return flag indicating if specified API name exists
    """
    def _isSoapApiDefined(self, apiName: str) -> bool:
        try:
            method = getattr(self.client.service, apiName)
            return True
        except Exception as e:
            return False

    """
    verify against wsdl that the specified SOAP API is defined for the current client, 
    and if so we will attempt to call it and return the result
    """
    def _callSoapApi(self, apiName: str, logTag: str) -> str:
        if (not self._isSoapApiDefined(apiName)):
            raise Exception("%s SOAP API not defined: %s, wsdl: %s", logTag, apiName, self.wsdlUrl)

        self.tracer.info("%s SOAP API executing: %s, wsdl: %s", logTag, apiName, self.wsdlUrl)

        startTime = time()
        try:
            method = getattr(self.client.service, apiName)
            result = method()
            self.tracer.info("%s SOAP API success for %s, wsdl: %s [%d ms]",
                             logTag, apiName, self.wsdlUrl, TimeUtils.getElapsedMilliseconds(startTime))

            return result
        except Exception as e:
            self.tracer.error("%s SOAP API error for %s, wsdl: %s [%d ms] %s",
                              logTag, apiName, self.wsdlUrl, TimeUtils.getElapsedMilliseconds(startTime), e, exc_info=True)
            raise e