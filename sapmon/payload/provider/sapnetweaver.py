# Python modules
import json
import logging
from datetime import datetime, timedelta, timezone
from time import time
from typing import Any, Callable, Dict, Optional
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
from const import *
from helper.azure import AzureStorageAccount
from helper.context import *
from helper.tools import *
from provider.base import ProviderInstance, ProviderCheck
from netweaver.metricclientfactory import NetWeaverMetricClient, NetWeaverSoapClientBase, ServerTimeClientBase, MetricClientFactory
from netweaver.rfcsdkinstaller import PATH_RFC_SDK_INSTALL, SapRfcSdkInstaller
from netweaver.soapclient import NetWeaverSoapClient
from typing import Dict

# Suppress SSLError warning due to missing SAP server certificate
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# wait time in between attempts to re-download and install RFC SDK package if we have a download blob
# URL defined and previous install attempt was not successful
MINIMUM_RFC_INSTALL_RETRY_INTERVAL = timedelta(minutes=30)

# timeout to use for all SOAP WSDL fetch and other API calls
SOAP_API_TIMEOUT_SECS = 5

# soap client cache expiration, after which amount of time both successful + failed soap client instantiation attempts will be refreshed
SOAP_CLIENT_CACHE_EXPIRATIION = timedelta(minutes=10)

# hard-coded mapping of Provider Check names that map to specific SOAP API actions 
# (usually check name and API name are the same but not required to be)
SOAP_PROVIDER_CHECK_API_MAPPINGS = {'GetSystemInstanceList': 'GetSystemInstanceList',
                                    'GetProcessList': 'GetProcessList', 
                                    'ABAPGetWPTable': 'ABAPGetWPTable',
                                    'GetQueueStatistic': 'GetQueueStatistic',
                                    'EnqGetStatistic': 'EnqGetStatistic'}


SOAP_ERROR_UNAUTHORIZED = "HTTP 401 Unauthorized"
SOAP_ERROR_NAME_RESOLUTION = "Name Resolution Failure"
SOAP_ERROR_TIMEOUT = "Connection timed out"
SOAP_ERROR_CONNECTION = "Connection refused"
SOAP_ERROR_CLIENT_FAILURE = "SOAP client initialization failure"
SOAP_ERROR_UNKNOWN = "Unknown Error"

class sapNetweaverProviderInstance(ProviderInstance):
    # static / class variables to enforce singleton behavior around rfc sdk installation attempts across all 
    # instances of SAP Netweaver provider
    _isRfcInstalled = None
    _rfcInstallerLock = Lock()

    def __init__(self,
                tracer: logging.Logger,
                ctx: Context,
                providerInstance: Dict[str, str],
                skipContent: bool = False,
                **kwargs) -> None:
        self.sapSid = None
        self.sapHostName = None
        self.sapInstanceNr = None
        self.sapSubdomain = None

        # RFC SDK call settings
        self.sapUsername = None
        self.sapPassword = None
        self.sapClientId = None
        self.sapRfcSdkBlobUrl = None
        self.sapLogonGroup = None

        # provider instance flag for whether RFC calls should be enabled for this specific Netweaver provider instance
        self._areRfcCallsEnabled = None

        # cache WSDL SOAP clients so we can re-use them across checks for the same provider and cut down off-box calls
        self._soapClientCache = {}

        # the RFC SDK does not allow client to specify a timeout and in fact appears to have a connection timeout of 60 secs. 
        # In cases where RFC calls timeout due to some misconfiguration, multiple retries can lead to metric gaps of several minutes.  
        # We are limiting retries here because it is extremely rare for SOAP or RFC call to fail on first attempt and succeed on retry,
        # as most of these failures are due to persistent issues.  Better to not waste limited time budget.
        retrySettings = {
            "retries": 1,
            "delayInSeconds": 1,
            "backoffMultiplier": 2
        }

        super().__init__(tracer,
                       ctx,
                       providerInstance,
                       retrySettings,
                       skipContent,
                       **kwargs)

    """
    parse provider properties and get sid, host name and instance number
    """
    def parseProperties(self) -> bool:
        self.sapSid = self.metadata.get("sapSid", "")
        if not self.sapSid:
            self.tracer.error("%s sapSid cannot be empty", self.fullName)
            return False

        # provider level common logging prefix
        self.logTag = "[%s][%s]" % (self.fullName, self.sapSid)

        self.sapHostName = self.providerProperties.get("sapHostName", None)
        if not self.sapHostName:
            self.tracer.error("%s sapHostName cannot be empty", self.logTag)
            return False

        instanceNr = self.providerProperties.get("sapInstanceNr", None)
        if instanceNr is None: # 0 is an acceptable value for Instance Number
            self.tracer.error("%s sapInstanceNr cannot be empty", self.logTag)
            return False
        if not type(instanceNr) is int or instanceNr < 0 or instanceNr > 98:
            self.tracer.error("%s sapInstanceNr can only be between 00 and 98 but %s was passed", self.logTag, str(instanceNr))
            return False
        self.sapInstanceNr = str(instanceNr).zfill(2)
        self.sapSubdomain = self.providerProperties.get("sapSubdomain", "")

        self.sapUsername = self.providerProperties.get('sapUsername', None)
        self.sapPassword = self.providerProperties.get('sapPassword', None)
        self.sapClientId = self.providerProperties.get('sapClientId', None)
        self.sapLogonGroup = self.providerProperties.get('sapLogonGroup',None)
        self.sapRfcSdkBlobUrl = self.providerProperties.get('sapRfcSdkBlobUrl', None)

        # if user did not specify password directly via UI, check to see if they instead
        # provided link to Key Vault secret
        if not self.sapPassword:
            sapPasswordKeyVaultUrl = self.providerProperties.get("sapPasswordKeyVaultUrl", None)
            if sapPasswordKeyVaultUrl:
                self.tracer.info("%s sapPassword key vault URL specified, attempting to fetch from %s", self.logTag, sapPasswordKeyVaultUrl)

                try:
                    keyVaultUrlPatternMatch = re.match(REGEX_EXTERNAL_KEYVAULT_URL,
                                                       sapPasswordKeyVaultUrl,
                                                       re.IGNORECASE)
                    keyVaultName = keyVaultUrlPatternMatch.group(1)
                    secretName = keyVaultUrlPatternMatch.group(2)
                except Exception as e:
                    self.tracer.error("%s invalid sapPassword Key Vault secret url format: %s", self.logTag, sapPasswordKeyVaultUrl)
                    return False
                
                try:
                    kv = AzureKeyVault(self.tracer, keyVaultName, self.ctx.msiClientId)
                    self.sapPassword = kv.getSecret(secretName, None).value

                    if not self.sapPassword:
                        raise Exception("failed to read sapPassword secret")
                except Exception as e:
                    self.tracer.error("%s error fetching sapPassword secret from keyVault url: %s, %s",
                                      self.logTag, 
                                      sapPasswordKeyVaultUrl, 
                                      e)
                    return False

        return True

    """
    return a netweaver RFC client initialized with "MESSAGESERVER" instance we find
    for this SID.  
    """
    def getRfcClient(self, logTag: str) -> NetWeaverMetricClient:
        # RFC connections against application server instances can be made through 'MESSAGESERVER' instances
        dispatcherInstance = self.getMessageServerInstance()

        return MetricClientFactory.getMetricClient(tracer=self.tracer, 
                                                   logTag=logTag,
                                                   sapHostName=dispatcherInstance['hostname'],
                                                   sapSysNr=str(dispatcherInstance['instanceNr']),
                                                   sapSubdomain=self.sapSubdomain,
                                                   sapSid=self.sapSid,
                                                   sapClient=str(self.sapClientId),
                                                   sapLogonGroup = self.sapLogonGroup,
                                                   sapUsername=self.sapUsername,
                                                   sapPassword=self.sapPassword)

    def validate(self) -> bool:
        logTag = "[%s][%s][validation]" % (self.fullName, self.sapSid)

        # HACK: Load content json to fetch the list of APIs in the checks
        self.initContent()

        try:
            self._validateSoapClient()
        except Exception as e:
            self.tracer.error("%s SOAP API validation failure: %s", logTag, e, exc_info=True)
            return False

        try:
            self._validateRfcClient()
        except Exception as e:
            self.tracer.error("%s RFC client validation failure: %s", logTag, e, exc_info=True)
            return False

        return True

    """
    iterate through all SOAP API calls and attempt to validate that SOAP API client can be instantiated
    and expected APIs are callable
    """
    def _validateSoapClient(self) -> None:
        logTag = "[%s][%s][validation]" % (self.fullName, self.sapSid)

        self.tracer.info("%s validate SOAP API connectivity", logTag)

        validationErrors = []

        try:
            # first get list of SAP system instances
            apiName = 'GetSystemInstanceList'
            instances = self._validateGetSystemInstanceList(logTag="%s[%s]" % (logTag, apiName))

            apiName = 'GetProcessList'
            apiErrorCounts = self._validateGetProcessList(logTag="%s[%s]" % (logTag, apiName), instances=instances)
            apiErrorMsg = self._getValidationErrorsMessage(apiErrorCounts)
            if (apiErrorMsg):
                validationErrors.append("%s: %s" % (apiName, apiErrorMsg))

            apiName = 'ABAPGetWPTable'
            apiErrorCounts = self._validateABAPGetWPTable(logTag="%s[%s]" % (logTag, apiName), instances=instances)
            apiErrorMsg = self._getValidationErrorsMessage(apiErrorCounts)
            if (apiErrorMsg):
                validationErrors.append("%s: %s" % (apiName, apiErrorMsg))

            apiName = 'GetQueueStatistic'
            apiErrorCounts = self._validateGetQueueStatistic(logTag="%s[%s]" % (logTag, apiName), instances=instances)
            apiErrorMsg = self._getValidationErrorsMessage(apiErrorCounts)
            if (apiErrorMsg):
                validationErrors.append("%s: %s" % (apiName, apiErrorMsg))

            apiName = 'EnqGetStatistic'
            apiErrorCounts = self._validateEnqGetStatistic(logTag="%s[%s]" % (logTag, apiName), instances=instances)
            apiErrorMsg = self._getValidationErrorsMessage(apiErrorCounts)
            if (apiErrorMsg):
                validationErrors.append("%s: %s" % (apiName, apiErrorMsg))

            if (len(validationErrors) > 0):
                errorMsg = ', '.join(validationErrors)
                raise Exception("SOAP API validation errors: %s" % (errorMsg))

            self.tracer.info("%s SOAP client API validated successfully for SAP system", logTag)

        except Exception as e:
            self.tracer.error("%s error occurred while validating SOAP client API calls for SAP system: %s",
                              logTag,
                              e,
                              exc_info=True)
            raise

    def _validateGetSystemInstanceList(self, logTag: str) -> list:
        client = MetricClientFactory.getSoapMetricClientForSapInstance(tracer=self.tracer,
                                                                       logTag=logTag,
                                                                       sapSid=self.sapSid,
                                                                       sapHostName=self.sapHostName,
                                                                       sapSubdomain=self.sapSubdomain,
                                                                       sapInstanceNr=self.sapInstanceNr,
                                                                       useCache=False)
        
        return client.getSystemInstanceList(logTag=logTag)

    def _validateGetProcessList(self, logTag: str, instances: list) -> None:
        # the filtered list of SAP instances that should support this SOAP API
        filteredInstances = self._getFilteredInstancesForSoapApiAction(instances, 
                                                                       checkName="GetProcessList", 
                                                                       apiName="GetProcessList")

        # SOAP client API to invoke
        clientMethod = lambda logTag, client: client.getProcessList(logTag=logTag)

        # invoke the SOAP API for all instanes and return aggregate errors summary
        return self._validateSoapApiForInstances(logTag=logTag, 
                                                 instances=filteredInstances, 
                                                 clientMethod=clientMethod)

    def _validateABAPGetWPTable(self, logTag: str, instances: list) -> None:
        # the filtered list of SAP instances that should support this SOAP API
        filteredInstances = self._getFilteredInstancesForSoapApiAction(instances, 
                                                                       checkName="ABAPGetWPTable", 
                                                                       apiName="ABAPGetWPTable")

        # SOAP client API to invoke
        clientMethod = lambda logTag, client: client.getAbapWorkerProcessTable(logTag=logTag)

        # invoke the SOAP API for all instanes and return aggregate errors summary
        return self._validateSoapApiForInstances(logTag=logTag, 
                                                 instances=filteredInstances, 
                                                 clientMethod=clientMethod)
    
    def _validateGetQueueStatistic(self, logTag: str, instances: list) -> None:
        # the filtered list of SAP instances that should support this SOAP API
        filteredInstances = self._getFilteredInstancesForSoapApiAction(instances, 
                                                                       checkName="GetQueueStatistic", 
                                                                       apiName="GetQueueStatistic")

        # SOAP client API to invoke
        clientMethod = lambda logTag, client: client.getQueueStatistic(logTag=logTag)

        # invoke the SOAP API for all instanes and return aggregate errors summary
        return self._validateSoapApiForInstances(logTag=logTag, 
                                                 instances=filteredInstances, 
                                                 clientMethod=clientMethod)

    def _validateEnqGetStatistic(self, logTag: str, instances: list) -> None:
        # the filtered list of SAP instances that should support this SOAP API
        filteredInstances = self._getFilteredInstancesForSoapApiAction(instances, 
                                                                       checkName="EnqGetStatistic", 
                                                                       apiName="EnqGetStatistic")

        # SOAP client API to invoke
        clientMethod = lambda logTag, client: client.getEnqueueServerStatistic(logTag=logTag)

        # invoke the SOAP API for all instanes and return aggregate errors summary
        return self._validateSoapApiForInstances(logTag=logTag, 
                                                 instances=filteredInstances, 
                                                 clientMethod=clientMethod)

    """
    attempt to invoke specific SOAP client method against all SAP instances and return
    aggregate counts of all different error types encountered
    """
    def _validateSoapApiForInstances(self, 
                                     logTag: str, 
                                     instances: list, 
                                     clientFunc: Callable[[str, NetWeaverSoapClientBase], list]) -> dict:
        # initialize empty structure to hold validation error aggregate count by category
        validationErrors = self._initializeValidationErrorsSummary()

        for instance in instances:
            try:
                client = MetricClientFactory.getSoapMetricClientForSapInstance(tracer=self.tracer,
                                                                               logTag=logTag,
                                                                               sapSid=self.sapSid,
                                                                               sapHostName=instance['hostname'],
                                                                               sapSubdomain=self.sapSubdomain,
                                                                               sapInstanceNr=instance['instanceNr'],
                                                                               useCache=True)

                clientFunc(logTag, client)
            except Exception as e:
                # try to categorize exception here
                errorType = self._categorizeSoapApiException(ex=e)
                if (errorType not in validationErrors):
                    validationErrors[errorType] = []
                
                #  add this "{hostname}_{instanceNr}" to to the list of instances with this error type
                validationErrors[errorType].append("%s_%s" % (instance['hostname'], instance['instanceNr']))
            
        return validationErrors

    """
    attempt to categorize SOAP API exception message into a known error type (for aggregation)
    """
    def _categorizeSoapApiException(self, ex: Exception) -> str:
        # SOAP API permissions
        #   Error 401: HTTP 401 Unauthorized [14 ms]
        # Name Resolution Failures
        #   HTTPConnectionPool(host='fu1asc', port=8100): Max retries exceeded with url: / (Caused by NewConnectionError('&lt;urllib3.connection.HTTPConnection object at 0x7fcd12471610&gt;: Failed to establish a new connection: [Errno -2] Name or service not known')) 
        #   HTTPSConnectionPool(host='msabwhana20-li2', port=50014): Max retries exceeded with url: /?wsdl (Caused by NewConnectionError('&lt;urllib3.connection.HTTPSConnection object at 0x7f78f61cc8d0&gt;: Failed to establish a new connection: [Errno -3] Temporary failure in name resolution')) [41 ms]
        #   NewConnectionError('&lt;urllib3.connection.HTTPConnection object at 0x7f6e1f566dd0&gt;: Failed to establish a new connection: [Errno -5] No address associated with hostname'))
        # Connection Time Outs
        #   HTTPSConnectionPool(host='cldazdci02.global.corp', port=52114): Read timed out. (read timeout=5) [5017 ms]
        #   HTTPConnectionPool(host='vhmclse2ci.mcl.tagmclarengroup.com', port=8101): Max retries exceeded with url: / (Caused by NewConnectionError('&lt;urllib3.connection.HTTPConnection object at 0x7fe9ba7ecf90&gt;: Failed to establish a new connection: [Errno 110] Connection timed out')) 
        # Connection Refused
        #   HTTPConnectionPool(host='server01', port=8100): Max retries exceeded with url: / (Caused by NewConnectionError('&lt;urllib3.connection.HTTPConnection object at 0x7fac59063fd0&gt;: Failed to establish a new connection: [Errno 111] Connection refused',)) 
        exStr = str(ex)
        if "401 Unauthorized" in exStr:
            return SOAP_ERROR_UNAUTHORIZED
        elif ("Name or service not known"  in exStr or 
              "Temporary failure in name resolution" in exStr or 
              "No address associated with hostname" in exStr):
            return SOAP_ERROR_NAME_RESOLUTION
        elif "timed out" in exStr:
            return SOAP_ERROR_TIMEOUT
        elif "Connection refused" in exStr:
            return SOAP_ERROR_CONNECTION
        elif "cached NetWeaverSoapClient failure" in exStr:
            return SOAP_ERROR_CLIENT_FAILURE
        else:
            return SOAP_ERROR_UNKNOWN

    """
    initialize a new validation errors summary table
    """
    def _initializeValidationErrorsSummary(self) -> dict:
        return { 
                 SOAP_ERROR_UNAUTHORIZED: [],
                 SOAP_ERROR_NAME_RESOLUTION: [],
                 SOAP_ERROR_TIMEOUT: [],
                 SOAP_ERROR_CONNECTION: [], 
                 SOAP_ERROR_CLIENT_FAILURE: [],
                 SOAP_ERROR_UNKNOWN: [] 
               }

    """
    parse validation errors table and return as a summary string (JSON) if there were validation failures,
    otherwise return None
    """
    def _getValidationErrorsMessage(self, validationErrors: dict) -> str:
        hasValidationErrors = False
        for errorType in validationErrors.keys:
            # TODO: may want to add special handling for certain error types so they are ignored 
            # and not treated as validation errors.  Right now, any error is treated as failure.
            if (validationErrors[errorType] and len(validationErrors[errorType]) > 0):
                hasValidationErrors = True

        if hasValidationErrors:
            return json.dumps(validationErrors, sort_keys=True, indent=4, cls=JsonEncoder)
        else:
            return None

    """
    return a filtered list of SAP instances that match the expected SAP features
    based on the provider check configuration properties
    """
    def _getFilteredInstancesForSoapApiAction(self, 
                                              instances: list, 
                                              checkName: str, 
                                              apiName: str) -> list:
        # parse provider config check properties (which come from JSON config file) to determine
        # which instance filter types (ie. include|exclude) and SAP feature names (ie. ABAP,ENQUE,etc...)
        # are supported by this SOAP API action
        parameters = self._getParametersForSoapApiAction(checkName=checkName, apiName=apiName)

        filterFeatures = parameters.get('filterFeatures', None)
        filterType = parameters.get('filterType', None)

        # now return filtered list of instances based the SAP feature that support this SOAP API
        return self.filterInstancesByFeature(instances, filterFeatures=filterFeatures, filterType=filterType)

    """
    iterate through provider check configurations and return the filtering parameters for the matching SOAP API
    check and the first matching API action name.  This is needed so we can validate SOAP API calls by 
    loading the same filter config parameters that are used when the metric collection action is executed as part of a monitor check
    {
        "name": "GetQueueStatistic",
        "description": "SAP Netweaver GetQueueStatistic",
        "customLog": "SapNetweaver_GetQueueStatistic",
        "frequencySecs": 60,
        "includeInCustomerAnalytics": true,
        "actions": [
            {
                "type": "ExecuteGenericWebServiceRequest",
                "parameters": {
                    "apiName": "GetQueueStatistic",
                    "filterFeatures": ["ABAP", "J2EE", "JEE"],
                    "filterType": "include"
                }
            }
        ]
    },
    """
    def _getParametersForSoapApiAction(self, checkName: str, apiName: str) -> dict:
        for check in self.checks:
            if (check.name != checkName):
                continue
            for action in check.actions:
                parameters = action.get("parameters", {})
                if (action.parameters.get('apiName', '') == apiName):
                    # stop after we find the first API action with the expected name
                    return parameters

        # no matching parameters for for check + api, so
        return {}

    """
    if customer provided RFC SDK configuration, then validate that all required properties are specified
    and validate we can establish RFC client connections to APIs we need to call
    """
    def _validateRfcClient(self) -> None:
        logTag = "[%s][%s][validation]" % (self.fullName, self.sapSid)

        # skip install if no RFC config properties are populated
        if (not self.sapUsername and
            not self.sapPassword and
            not self.sapClientId and
            not self.sapLogonGroup and
            not self.sapRfcSdkBlobUrl):
            # customer has not chosen to enable RFC SDK, nothing to validate
            return

        # ensure all required RFC properties are specified
        if (not self.sapUsername or
            not self.sapPassword or
            not self.sapClientId or
            not self.sapLogonGroup or
            not self.sapRfcSdkBlobUrl):
            # customer specified only partial set of config properties needed to enable RFC, so fail validation
            raise Exception("must specify all properties to enable RFC metric collection:  Username, Password, ClientId, and RfcSdkBlobUrl")

        if (not self.areRfcMetricsEnabled()):
            raise Exception("RFC SDK failed to install and is not usable")

        # initialize a client for the first healthy ABAP/Dispatcher instance we find
        client = self.getRfcClient(logTag=logTag)

        # update logging prefix with the specific instance details of the client
        sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
        
        # get metric query window to lookback 10 minutes to see if any results are available.  If not that probably
        # indicates customer has not enabled SMON on their SAP system
        self.tracer.info("%s attempting to fetch server timestamp from %s", logTag, sapHostnameStr)
        (startTime, endTime) = client.getQueryWindow(lastRunServerTime=None, 
                                                     minimumRunIntervalSecs=600)

        self.tracer.info("%s attempting to fetch SMON metrics from %s", logTag, sapHostnameStr)
        result = client.getSmonMetrics(startDateTime=startTime, endDateTime=endTime)
        self.tracer.info("%s successfully queried SMON metrics from %s", logTag, sapHostnameStr)

        self.tracer.info("%s attempting to fetch SWNC workload metrics from %s", logTag, sapHostnameStr)
        result = client.getSwncWorkloadMetrics(startDateTime=startTime, endDateTime=endTime)
        self.tracer.info("%s successfully queried SWNC workload metrics from %s", logTag, sapHostnameStr)

        self.tracer.info("%s attempting to fetch Short Dump metrics from %s", logTag, sapHostnameStr)
        result = client.getShortDumpsMetrics(startDateTime=startTime, endDateTime=endTime)
        self.tracer.info("%s successfully queried Short Dump metrics from %s", logTag, sapHostnameStr)

        self.tracer.info("%s successfully validated all known RFC SDK calls", logTag)

    """
    query SAP SOAP API to return list of all instances in the SID, but if caller specifies that cached results are okay
    and we have cached instance list with the provider instance, then just return the cached results
    """
    def getInstances(self, 
                     filterFeatures: list = None , 
                     filterType: str = None, 
                     useCache: bool = True) -> list:
        # Use cached list of instances if available since they should not change within a single monitor run;
        # but if cache is not available or if caller explicitly asks to skip cache then make the SOAP call
        if ('hostConfig' in self.state and useCache):
            # self.tracer.debug("%s using cached list of system instances", self.logTag)
            return self.filterInstancesByFeature(self.state['hostConfig'], filterFeatures=filterFeatures, filterType=filterType)

        self.tracer.info("%s getting list of system instances", self.logTag)
        startTime = time()

        instanceList = []
        hosts = self._getHosts()

        # Use last known hosts to fetch the updated list of hosts
        # Walk through the known hostnames and stop whenever any of them returns the list of all instances
        isSuccess = False
        for host in hosts:
            hostname, instanceNum, httpProtocol, port = host[0], host[1], host[2], host[3]

            try:
                # if we have a cached host config with already defined protocol and port, then we can initialize
                # client directly from that, otherwise we have to instantiate client using ports derived from the instance number
                # which will try the derived HTTPS port first and then fallback to derived HTTP port
                if (not httpProtocol or not port):
                    # client = self.getDefaultClient(hostname=hostname, instance=instanceNum)
                    # get SOAP client for the default port(s) based on the SAP instance number.
                    client = MetricClientFactory.getSoapMetricClientForSapInstance(tracer=self.tracer,
                                                                                   logTag=self.logTag,
                                                                                   sapSid=self.sapSid,
                                                                                   sapHostName=hostname,
                                                                                   sapSubdomain=self.sapSubdomain,
                                                                                   sapInstanceNr=instanceNum,
                                                                                   useCache=True)
                else:
                    # client = self.getClient(hostname, httpProtocol, port)
                    # get SOAP client for the specified hostname, HTTP protocol, and port
                    client = MetricClientFactory.getSoapMetricClientForHostAndPort(tracer=self.tracer,
                                                                                   logTag=self.logTag,
                                                                                   sapSid=self.sapSid,
                                                                                   sapHostName=hostname,
                                                                                   sapSubdomain=self.sapSubdomain,
                                                                                   sapInstanceNr=instanceNum,
                                                                                   httpProtocol=httpProtocol,
                                                                                   httpPort=port,
                                                                                   useCache=True)

                instanceList = client.getSystemInstanceList(logTag=self.logTag)

                # cache latest results in provider state
                self.state['hostConfig'] = instanceList

                isSuccess = True
                break
            except Exception as e:
                self.tracer.error("%s could not connect to SAP with hostname: %s and port: %s", self.logTag, hostname, port, exc_info=True)

        if not isSuccess:
            raise Exception("%s could not connect to any SAP instances with hosts %s [%d ms]" % \
                            (self.logTag, hosts, TimeUtils.getElapsedMilliseconds(startTime)))

        self.tracer.info("%s finished getting all system instances [%d ms]", self.logTag, TimeUtils.getElapsedMilliseconds(startTime))

        return self.filterInstancesByFeature(instanceList, filterFeatures=filterFeatures, filterType=filterType)

    """
    fetch cached instance list for this provider and filter down to the list 'ABAP' feature functions
    that are healthy (ie. have dispstatus attribute of 'SAPControl-GREEN').  Just return first in the list.
    """
    def getActiveDispatcherInstance(self):
        # Use cached list of instances if available since they don't change that frequently,
        # and filter down to only healthy dispatcher instances since RFC direct application server connection
        # only works against dispatchera
        dispatcherInstances = self.getInstances(filterFeatures=['ABAP'], filterType='include', useCache=True)
        healthyInstances = [instance for instance in dispatcherInstances if 'GREEN' in instance['dispstatus']]

        if (len(healthyInstances) == 0):
            raise Exception("No healthy ABAP/dispatcher instance found for %s" % self.sapSid)

        # return first healthy instance in list
        return healthyInstances[0]
    
    """
    fetch cached instance list for this provider and filter down to the list 'MESSAGESERVER' feature functions
    return the available message server
    """
    def getMessageServerInstance(self):
        # Use cached list of instances if available since they don't change that frequently,
        # and filter down to only healthy dispatcher instances since RFC direct application server connection
        # only works against dispatchera
        dispatcherInstances = self.getInstances(filterFeatures=['MESSAGESERVER'], filterType='include', useCache=True)
        
        if (len(dispatcherInstances) == 0):
            raise Exception("No MESSAGESERVER instance found for %s" % self.sapSid)
        
        # return first healthy instance in list
        return dispatcherInstances[0]
    
    """
    given a list of sap instances and a set of instance features (ie. functions) to include or exclude,
    apply filtering logic and return only those instances that match the filter conditions:
        'include' filter type will include any instance that matches any of the feature filters
        'exclude' filter type will exclude any instance that matches any of the feature filters
    """
    def filterInstancesByFeature(self, 
                                 sapInstances: list, 
                                 filterFeatures: list = None, 
                                 filterType: str = None) -> list:
        if (not filterFeatures or len(filterFeatures) == 0 or not sapInstances):
            return sapInstances
    
        self.tracer.info("%s filtering list of system instances based on features: %s", self.logTag, filterFeatures)

        instances = [(instance, instance['features'].split('|')) for instance in sapInstances]
       
        if filterType == "include":
            # Inclusion filter
            # Only include instances that match at least one of the filter features
            filtered_instances = [instance for (instance, instance_features) in instances \
                if not set(filterFeatures).isdisjoint(set(instance_features))]
        elif filterType == "exclude":
            # Exclusion filter
            # Only include instance that match none of the filter features
            filtered_instances = [instance for (instance, instance_features) in instances \
                if set(filterFeatures).isdisjoint(set(instance_features))]
        else:
            raise Exception("%s filterType '%s' is not supported filter type" % (self.logTag, filterType))

        return filtered_instances

    """
    query SAP system to return the current system timestamp approximation
    NOTE: this can be done different ways, for example by RFC calls, but since RFC calls are optional
    in the current design we do this instead by making simple HTTP request to the Message Server instance
    which will echo back the current server time using HTTP Response header named 'date'
    """
    def getServerTimestamp(self, logTag: str) -> datetime:
        messageServerInstance = self.getMessageServerInstance()
        hostname = messageServerInstance['hostname']
        instanceNr = messageServerInstance['instanceNr']

        client = MetricClientFactory.getMessageServerClientForSapInstance(tracer=self.tracer,
                                                                          logTag=logTag, 
                                                                          sapSid=self.sapSid,
                                                                          sapHostName=hostname,
                                                                          sapSubdomain=self.sapSubdomain,
                                                                          sapInstanceNr=instanceNr)

        return client.getServerTimestamp(logTag=logTag)

    """
    private method to return default provider hostname config (what customer provided at time netweaver provided was added)
    or a fully fleshed out list of <hostname / instance # / https:Port> tuples based on a previous cached call to getInstances()
    """
    def _getHosts(self) -> list:
        # Fetch last known list from storage. If storage does not have list, use provided
        # hostname and instanceNr
        if 'hostConfig' not in self.state:
            self.tracer.info("%s no host config persisted yet, using user-provided host name and instance nr", self.logTag)
            hosts = [(self.sapHostName,
                      self.sapInstanceNr,
                      None,
                      None)]
        else:
            self.tracer.info("%s fetching last known host config", self.logTag)
            currentHostConfig = self.state['hostConfig']
            hosts = [(hostConfig['hostname'], 
                      hostConfig['instanceNr'], 
                      "https" if (hostConfig['httpsPort'] and hostConfig['httpsPort'] != "0") else "http", 
                      hostConfig['httpsPort'] if (hostConfig['httpsPort'] and hostConfig['httpsPort'] != "0") else hostConfig['httpPort']) for hostConfig in currentHostConfig]

        return hosts

    """
    returns flag to indicate whether provider checks should attempt to use RFC SDK client calls to fetch certain metrics.
    First time may perform fairly expensive checks to validate if RFC SDK is installed anc configured, and may attempt
    to download user provided blob to install to local system.  We only want to attempt this at most once per process,
    so first caller to this function will pay that cost and the resulting success/failure flag will be cached.
    """
    def areRfcMetricsEnabled(self) -> bool:
        if self._areRfcCallsEnabled != None:
            # the flag for whether RFC is usable has already been initialzed, so return 
            return self._areRfcCallsEnabled

        # there may be 1..N sapNetWeaverProviderInstance instances per sapmon process, and each instance
        # may choose to enable/disable RFC calls individually, but we should only attempt to install the 
        # RFC SDK at most once per process.  Use a static/class variable to determine if installation 
        # attempt has already been attempted and was success/failure, and do all this inside of 
        # a lock and cache flag for future checks
        try:
            # class singleton lock
            sapNetweaverProviderInstance._rfcInstallerLock.acquire(blocking=True)

            # check -> lock -> check
            if (self._areRfcCallsEnabled != None):
                # flag was initialized prior to obtaining the lock
                return self._areRfcCallsEnabled

            # ensure this provider instance has necessary config settings to enable RFC SDK calls
            if (not self.sapUsername or
                not self.sapPassword or
                not self.sapClientId or
                not self.sapRfcSdkBlobUrl or
                not self.sapLogonGroup):
                self.tracer.info("%s Netweaver RFC calls disabled for because missing one or more required " +
                                 "config properties: sapUsername, sapPassword, sapClientId, sapLogonGroup and sapRfcSdkBlobUrl",
                                 self.logTag)
                self._areRfcCallsEnabled = False
                return False

            # only attempt to install RFC SDK once per process execution
            if (sapNetweaverProviderInstance._isRfcInstalled == None):
                sapNetweaverProviderInstance._isRfcInstalled = self._trySetupRfcSdk()
                
            self._areRfcCallsEnabled = sapNetweaverProviderInstance._isRfcInstalled

            return self._areRfcCallsEnabled

        except Exception as e:
            self.tracer.error("%s Exception trying to check if rfc sdk metrics are enabled, %s", self.logTag, e, exc_info=True)
            sapNetweaverProviderInstance._isRfcInstalled = False
            self._areRfcCallsEnabled = False

        finally:
            sapNetweaverProviderInstance._rfcInstallerLock.release()

        return False
    
    """
    validate that RFC SDK package has been installed and configured correctly and is usable by pyrfc module.
    If pyrfc module cannot be imported, then potentially attempt to download RFC SDK blob, install to local system,
    and configure necessary environment variables and system settings so that the libraries can be
    successfully loaded by the pyrfc module.  
    Returns flag indicating whether pyrfc module can be imnported (ie. whether RFC calls can be enabled)

    Pre-requisites for RFC SDK installation attempt:
    1.) Customer provided config property sapRfcSdkBlobUrl must be non-empty.
    2.) python module for "pynwrfc" must be installed
    3.) was the last failed SDK installation attempt more than N minutes ago (defined by MINIMUM_RFC_INSTALL_RETRY_INTERVAL)
    4.) does the sapRfcSdkBlobUrl provided by customer actually exist in the storage account
    5.) was the last_modified timestamp on the sapRfcSdkBlobUrl blob modified since the last failed installation attempt
    """
    def _trySetupRfcSdk(self) -> bool:
        try:
            # if no RFC SDK download blob url specified, treat as kill switch to disable any RFC calls
            if (not self.sapRfcSdkBlobUrl):
                self.tracer.info("%s No user provided RFC SDK blob url, will not leverage RFC SDK. quitting...", self.logTag)
                return False

            installer = SapRfcSdkInstaller(tracer=self.tracer, installPath=PATH_RFC_SDK_INSTALL)

            # environment variables must be initialized before RFC and pyrfc installation can be validated
            self.tracer.info("%s initializing RFC SDK environment...", self.logTag)
            if (not installer.initRfcSdkEnvironment()):
                self.tracer.error("%s failed to initialize rfc sdk environment pre-requisites", self.logTag)
                return False

            # if we are able to successfully import the pyrfc connector module, that means RFC SDK
            # libraries must be installed and were able to be found by pyrfc package initialization,
            # so no need to do any further checks.
            if (installer.isPyrfcModuleUsable()):
                # pyrfc package is usable, which means RFC SDK is already installed and environment configured correctly
                self.tracer.info("%s Pyrfc module is usable, RFC calls will be enabled", self.logTag)
                return True

            # if pyrfc module cannot be imported, check to see if it is even installed.  Assumption is that
            # pyrfc module is installed as part of container image, so if it is missing something is wrong
            # there is no need to even try to install the RFC SDK
            if (not installer.isPyrfcModuleInstalled()):
                self.tracer.error("%s Pyrfc module is not installed, RFC calls will be disabled", self.logTag)
                return False

            # check last sdk install attempt time so we can limit how often we retry
            # to download and install SDK on persistent failures (eg. no more than once every 30 mins)
            lastSdkInstallAttemptTime = installer.getLastSdkInstallAttemptTime()
            if (lastSdkInstallAttemptTime > (datetime.now(timezone.utc) - MINIMUM_RFC_INSTALL_RETRY_INTERVAL)):
                self.tracer.info("%s last RFC SDK install attempt was %s, minimum attempt retry %s, skipping...",
                                 self.logTag,
                                 lastSdkInstallAttemptTime, 
                                 MINIMUM_RFC_INSTALL_RETRY_INTERVAL)
                return False

            self.tracer.info("%s RFC SDK is not installed, so attempt installation now...", self.logTag)
            blobStorageAccount = AzureStorageAccount(tracer=self.tracer,
                                                     sapmonId=self.ctx.sapmonId,
                                                     msiClientId=self.ctx.msiClientId,
                                                     subscriptionId=self.ctx.vmInstance["subscriptionId"],
                                                     resourceGroup=self.ctx.vmInstance["resourceGroupName"])
    
            # first check that rfc sdk download blob exists in Azure Storage account, and if it 
            # exixts also fetch the last_modified timestamp metadata
            doesPackageExist, packageLastModifiedTime = installer.isRfcSdkAvailableForDownload(
                blobUrl=self.sapRfcSdkBlobUrl, 
                storageAccount=blobStorageAccount)

            if (not doesPackageExist):
                self.tracer.error("%s User provided RFC SDK blob does not exist %s, skipping...", self.logTag, self.sapRfcSdkBlobUrl)
                return False
            
            self.tracer.info("%s user provided RFC SDK blob exists for download %s, lastModified=%s",
                             self.logTag, self.sapRfcSdkBlobUrl, packageLastModifiedTime)
            
            # the user provided sdk blob exists, so before we download compare the last_modified timestamp
            # with the last modified time of the last download attempt.  If nothing has changed, 
            # then no need to try and download the package again
            # TODO:  confirm, should we go ahead and try to re-download previously failed packages
            #        once every 30 minutes anyway?  just in case failure was something external?
            lastInstallPackageModifiedTime = installer.getLastSdkInstallPackageModifiedTime()

            if (packageLastModifiedTime == lastInstallPackageModifiedTime):
                self.tracer.info("%s rfc sdk download package has not been modified since last download " +
                                 "attempt (last_modified=%s), will not download again",
                                 self.logTag, 
                                 lastInstallPackageModifiedTime)
                return False
            
            self.tracer.info("%s user provided rfc sdk package last_modified (%s) has changed " + 
                             "since last install attempt (%s), attempting to re-download and install",
                             self.logTag,
                             packageLastModifiedTime,
                             lastInstallPackageModifiedTime)

            # try to download user provided RFC SDK blob, install to local system and configure necessary
            # environment variables and system settings so that it can be usable by pyrfc module
            if (not installer.downloadAndInstallRfcSdk(blobUrl=self.sapRfcSdkBlobUrl, storageAccount=blobStorageAccount)):
                self.tracer.error("%s failed to download and install rfc sdk package, RFC calls will not be enabled...", self.logTag)
                return False

            # on Linux pyrfc module may not be usable upon first install attempt, as it appears that unpacking
            # libraries to the LD_LIBRARY_PATH env variable after the python process starts may not pick up the change.
            # The module should be usable on the next sapmon process run.
            if (not installer.isPyrfcModuleUsable()):
                self.tracer.error("%s pyrfc module still not usable after RFC SDK install (might require process restart), " + 
                                  "RFC calls will not be enabled...", 
                                  self.logTag)
                return False

            self.tracer.info("%s pyrfc module is usable after RFC SDK install, RFC calls will be enabled...", self.logTag)
            return True

        except Exception as e:
            self.tracer.error("%s exception trying to setup and validate RFC SDK, RFC calls will be disabled: %s", self.logTag, e, exc_info=True)

        return False


###########################
class sapNetweaverProviderCheck(ProviderCheck):
    lastResult = []

    # hard-coded set of action names that require RFC SDK to be usable 
    # and can override runtime isEnabled() check if RFC is not usable
    rfcCheckNames = {'SMON_Metrics', 'SWNC_Workload_Metrics', 'SDF_Short_Dumps_Metrics'}

    def __init__(self,
        provider: ProviderInstance,
        **kwargs
    ):
        super().__init__(provider, **kwargs)
        self.lastRunLocal = None
        self.lastRunServer = None

        # provider check common logging prefix
        self.logTag = "[%s][%s]" % (self.fullName, self.providerInstance.sapSid)

    """
    return flag indicating whether this check instances requires the SAP RFC SDK to be installed and usable
    """
    def doesCheckRequireRfcSdk(self) -> bool:
        return self.name in sapNetweaverProviderCheck.rfcCheckNames

    """
    override base ProviderCheck implementation to allow RFC metric collection methods enabled in
    the default Provider JSON configuration yet treated as disabled at runtime if RFC SDK
    is not configured (to reduce log spam)
    """
    def isEnabled(self) -> bool:
        if not self.state["isEnabled"]:
            return False
        
        # if this check requires RFC and RFC is not installed, then treat as disabled
        if (self.doesCheckRequireRfcSdk()):
            if (not self.providerInstance.areRfcMetricsEnabled()):
                return False

        return True
    
    ##############################
    # provider check action methods (to retrieve metrics and logs)
    ##############################

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch snapshot
    of metadata and availability for all instances in SAP system
    """
    def _actionGetSystemInstanceList(self) -> None:
        self.tracer.info("%s refreshing list of system instances", self.logTag)
        self.lastRunLocal = datetime.utcnow()
        self.lastRunServer = self.providerInstance.getServerTimestamp(logTag=self.logTag)

        # when performing the actual provider check action, always fetch fresh instance list snapshot 
        # so that we can refresh the cache
        instanceList = self.providerInstance.getInstances(useCache=False)

        # Update host config, if new list is fetched
        # Parse dictionary and add current timestamp and SID to data and log it
        if len(instanceList) != 0:
            currentTimestamp = self._getFormattedTimestamp()
            for instance in instanceList:
                instance['timestamp'] = currentTimestamp
                instance['serverTimestamp'] = self.lastRunServer.isoformat()
                instance['SID'] = self.providerInstance.sapSid
                instance['subdomain'] = self.providerInstance.sapSubdomain

        self.lastResult = instanceList

        # Update internal state
        if not self.updateState():
            raise Exception("%s failed to update state" % self.logTag)

        self.tracer.info("%s successfully fetched system instance list", self.logTag)

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch process list metadata 
    from all SAP application server instances
    """
    def _actionGetProcessList(self, apiName: str, filterFeatures: list, filterType: str) -> None:
        # define the SOAP API client function to invoke
        clientFunc = lambda logTag, client: client.getProcessList(logTag=logTag)
        # define function to remove sensitive data from SOAP API raw results
        sanitizeResultsFunc = lambda results: self._sanitizeGetProcessList(results)

        self._executeSoapApiForInstances(logTag=self.logTag, 
                                         apiName=apiName, 
                                         filterFeatures=filterFeatures, 
                                         filterType=filterType,
                                         clientFunc=clientFunc,
                                         sanitizeResultsFunc=sanitizeResultsFunc)

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch worker process queue metrics
    for all SAP application server instances that support ABAP function
    """
    def _actionGetQueueStatistic(self, apiName: str, filterFeatures: list, filterType: str) -> None:
        # define the SOAP API client function to invoke
        clientFunc = lambda logTag, client: client.getQueueStatistic(logTag=logTag)

        self._executeSoapApiForInstances(logTag=self.logTag, 
                                         apiName=apiName, 
                                         filterFeatures=filterFeatures, 
                                         filterType=filterType,
                                         clientFunc=clientFunc,
                                         sanitizeResultsFunc=None)

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch ABAP worker process metrics
    for all SAP application server instances that support ABAP function
    """
    def _actionABAPGetWPTable(self, apiName: str, filterFeatures: list, filterType: str) -> None:
        # define the SOAP API client function to invoke
        clientFunc = lambda logTag, client: client.getAbapWorkerProcessTable(logTag=logTag)

        # define function to remove sensitive data from SOAP API raw results
        sanitizeResultsFunc = lambda results: self._sanitizeABAPGetWPTable(results)

        self._executeSoapApiForInstances(logTag=self.logTag, 
                                         apiName=apiName, 
                                         filterFeatures=filterFeatures, 
                                         filterType=filterType,
                                         clientFunc=clientFunc,
                                         sanitizeResultsFunc=sanitizeResultsFunc)                                         

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch Enqueue server lock statistics
    for the SAP application server instance that supports the ENQUE function
    """
    def _actionEnqGetStatistic(self, apiName: str, filterFeatures: list, filterType: str) -> None:
        # define the SOAP API client function to invoke
        clientFunc = lambda logTag, client: client.getEnqueueServerStatistic(logTag=logTag)

        self._executeSoapApiForInstances(logTag=self.logTag, 
                                         apiName=apiName, 
                                         filterFeatures=filterFeatures, 
                                         filterType=filterType,
                                         clientFunc=clientFunc,
                                         sanitizeResultsFunc=None)

    """
    netweaver provider check action to query for SDF/SMON Analysis Run metrics
    """
    def _actionGetSmonAnalysisMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping SMON metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()
            
            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
            
            # get metric query window based on our last successful query where results were returned
            (startTime, endTime) = client.getQueryWindow(lastRunServerTime=self.lastRunServer, 
                                                         minimumRunIntervalSecs=self.frequencySecs)
            self.lastResult = client.getSmonMetrics(startDateTime=startTime, endDateTime=endTime)

            self.tracer.info("%s successfully queried SMON metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)
            self.lastRunServer = endTime

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch SMON Analysis Run metrics for %s [%d ms], error: %s", 
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise
    
    """
    netweaver provider check action to query for SWNC workload statistics and decorate with ST03 metric calculations
    """
    def _actionGetSwncWorkloadMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping SWNC metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
            
            # get metric query window based on our last successful query where results were returned
            (startTime, endTime) = client.getQueryWindow(lastRunServerTime=self.lastRunServer, 
                                                         minimumRunIntervalSecs=self.frequencySecs)

            self.lastResult = client.getSwncWorkloadMetrics(startDateTime=startTime, endDateTime=endTime)

            self.tracer.info("%s successfully queried SWNC workload metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)
            self.lastRunServer = endTime

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch SWNC workload metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise
    
    """
    netweaver provider check action to query for short dumps workload statistics
    """
    def _actionGetShortDumpsMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping short dumps metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
            
            # get metric query window based on our last successful query where results were returned
            (startTime, endTime) = client.getQueryWindow(lastRunServerTime=self.lastRunServer, 
                                                         minimumRunIntervalSecs=self.frequencySecs)

            self.lastResult = client.getShortDumpsMetrics(startDateTime=startTime, endDateTime=endTime)

            self.tracer.info("%s successfully queried short dumps workload metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)
            self.lastRunServer = endTime

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch short dumps workload metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise
    
    #####################
    # Provider check helper methods
    #####################

    def _getFormattedTimestamp(self) -> str:
        return datetime.utcnow().isoformat()

    """
    helper method to do following:
        1. filter list SAP system instances down to set that matches specific SAP Feature filter conditions
        2. invoke caller specified SOAP client method against filtered list of SAP instances
        3. santize results using caller specified method to remove PII fields we don't want to ingest to Log Analytics
        4. enrich metrics with common schema properties
        5. results from all instances are appended to a single list and returned
        6. save metric result set and "last run" state into provider check base class variables 
           so that they will be ingested to Log Analytics by sapmon framework
    """
    def _executeSoapApiForInstances(self, 
                                    logTag: str, 
                                    apiName: str,
                                    filterFeatures: list, 
                                    filterType: str,
                                    clientFunc: Callable[[str, NetWeaverSoapClientBase], list],
                                    sanitizeResultsFunc: Callable[[list], list] = None) -> list:
        self.lastRunLocal = datetime.utcnow()
        self.lastRunServer = self.providerInstance.getServerTimestamp(logTag=logTag)
        currentTimestamp = self._getFormattedTimestamp()

        # initialize empty structure to hold validation error aggregate count by category
        allResults = []

        # track latency of entire method excecution with dependencies
        startTime = time()
        
        # Use cached list of instances if available since they don't change that frequently; else fetch afresh.
        # filter down to just the instances we need for this SOAP API type
        sapInstances = self.providerInstance.getInstances(useCache=True, filterFeatures=filterFeatures, filterType=filterType)

        if len(sapInstances) == 0:
            self.tracer.info("%s no instances that support this API: %s", self.logTag, apiName)

        # keep track of total instances called for this API and total errors
        totalCount = 0
        errorCount = 0

        for instance in sapInstances:
            totalCount += 1

            # default to https unless the httpsPort was not defined, in which case fallback to http
            httpProtocol = "https"
            port = instance['httpsPort']
            if ((not port) or port == "0"):
                # fallback to http port instead
                httpProtocol = "http"
                port = instance['httpPort']

            results = []
            try:
                client = MetricClientFactory.getSoapMetricClientForHostAndPort(tracer=self.tracer,
                                                                               logTag=logTag,
                                                                               sapSid=self.providerInstance.sapSid,
                                                                               sapHostName=instance['hostname'],
                                                                               sapSubdomain=self.providerInstance.sapSubdomain,
                                                                               sapInstanceNr=instance['instanceNr'],
                                                                               httpProtocol=httpProtocol,
                                                                               httpPort=port,
                                                                               useCache=True)

                # invoke SOAP API for this instance client
                results = clientFunc(logTag, client)

                # if user provided a post-processing method to sanitize raw results, then invoke
                if sanitizeResultsFunc:
                    results = sanitizeResultsFunc(results)

                # decorate results with common metric schema properties
                if len(results) > 0:
                    for result in results:
                        result['hostname'] = instance['hostname']
                        result['instanceNr'] = instance['instanceNr']
                        result['subdomain'] = self.providerInstance.sapSubdomain
                        result['timestamp'] = currentTimestamp
                        result['serverTimestamp'] = self.lastRunServer.isoformat()
                        result['SID'] = self.providerInstance.sapSid
                    allResults.extend(results)

            except Exception as e:
                errorCount += 1
                # log the fully qualified hostname and exception
                wsdlUrl = NetWeaverSoapClient._getFullyQualifiedWsdl(instance['hostname'], self.providerInstance.sapSubdomain, httpProtocol, port)
                self.tracer.error("%s exception trying to call SOAP API %s url: %s, %s", logTag, apiName, wsdlUrl, e, exc_info=True)
                continue

        self.lastResult = allResults

        self.tracer.info("%s finished SOAP API: %s, %d results from %d instances with %d errors [%d ms]",
                         logTag, apiName, len(allResults), totalCount, errorCount, TimeUtils.getElapsedMilliseconds(startTime))

        if not self.updateState():
            raise Exception("%s failed to update state for web service request for SOAP API: %s" % (logTag, apiName))
            
        return allResults

    """
    Method to parse the value based on the key provided and set the values with None value to empty string ''
    """
    def _getKeyValue(self, dictionary, key, apiName):
            if key not in dictionary:
                raise ValueError("Result received for api %s does not contain key: %s"% (apiName, key))
            if(dictionary[key] == None):
                dictionary[key] = ""
            return dictionary[key]

    """
    Method to parse the results from ABAPGetWPTable and set the strings with None value to empty string ''
    """
    def _sanitizeABAPGetWPTable(self, records: list) -> list:
       apiName = "ABAPGetWPTable"
       processed_results = list()
       for record in records:
            processed_result = {
                "Action": self._getKeyValue(record, 'Action', apiName),
                "Client": self._getKeyValue(record, 'Client', apiName),
                "Cpu": self._getKeyValue(record, 'Cpu', apiName),
                "Err": self._getKeyValue(record, 'Err', apiName),
                "No": self._getKeyValue(record, 'No', apiName),
                "Pid": self._getKeyValue(record, 'Pid', apiName),
                "Program": self._getKeyValue(record, 'Program', apiName),
                "Reason": self._getKeyValue(record, 'Reason', apiName),
                "Sem": self._getKeyValue(record, 'Sem', apiName),
                "Start": self._getKeyValue(record, 'Start', apiName),
                "Status": self._getKeyValue(record, 'Status', apiName),
                "Table": self._getKeyValue(record, 'Table', apiName),
                "Time": self._getKeyValue(record, 'Time', apiName),
                "Typ": self._getKeyValue(record, 'Typ', apiName),
                "User": self._getKeyValue(record, 'User', apiName)
            }
            processed_results.append(processed_result)
       return processed_results

    """
    Method to parse the results from GetProcessList and set the strings with None value to empty string ''
    """
    def _sanitizeGetProcessList(self, records: list) -> list:
       apiName = "GetProcessList"
       processed_results = list()
       for record in records:
            processed_result = {
                "description": self._getKeyValue(record, 'description', apiName),
                "dispstatus": self._getKeyValue(record, 'dispstatus', apiName),
                "elapsedtime": self._getKeyValue(record, 'elapsedtime', apiName),
                "name": self._getKeyValue(record, 'name', apiName),
                "pid": self._getKeyValue(record, 'pid', apiName),
                "starttime": self._getKeyValue(record, 'starttime', apiName),
                "textstatus": self._getKeyValue(record, 'textstatus', apiName)
            }
            processed_results.append(processed_result)
       return processed_results

    def generateJsonString(self) -> str:
        self.tracer.info("%s converting result to json string", self.logTag)
        if self.lastResult is not None and len(self.lastResult) != 0:
            for result in self.lastResult:
                result['SAPMON_VERSION'] = PAYLOAD_VERSION
                result['PROVIDER_INSTANCE'] = self.providerInstance.name
                result['METADATA'] = self.providerInstance.metadata
    
        resultJsonString = json.dumps(self.lastResult, sort_keys=True, indent=4, cls=JsonEncoder)
        self.tracer.debug("%s resultJson=%s", self.logTag, str(resultJsonString))
        return resultJsonString

    def updateState(self) -> bool:
        self.tracer.info("%s updating internal state", self.logTag)
        self.state['lastRunLocal'] = self.lastRunLocal
        self.state['lastRunServer'] = self.lastRunServer
        self.tracer.info("%s internal state successfully updated", self.logTag)
        return True
