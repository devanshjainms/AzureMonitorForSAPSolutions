import json
from helper.context import *

SOAP_ERROR_UNAUTHORIZED = "HTTP 401 Unauthorized"
SOAP_ERROR_NAME_RESOLUTION = "Name Resolution Failure"
SOAP_ERROR_TIMEOUT = "Connection timed out"
SOAP_ERROR_CONNECTION = "Connection refused"
SOAP_ERROR_CLIENT_FAILURE = "SOAP client initialization failure"
SOAP_ERROR_UNKNOWN = "Unknown Error"

################
# Helper class to enapsulate simple classification of SOAP API client errors.  Used to keep running
# tally of Exceptions that have been thrown (along with list of hostnames tht observed that exception)
# so that summary validation status messages can be displayed.  Also to encapsulate (future) logic rules
# about what type of exceptions can/should be ignored for validation.
################
class SoapClientValidator:

    def __init__(self):
        # initialize a dictionary to hold categories SOAP Client errors by new validation errors summary table
        self.errorSummary = { 
                              SOAP_ERROR_UNAUTHORIZED: [],
                              SOAP_ERROR_NAME_RESOLUTION: [],
                              SOAP_ERROR_TIMEOUT: [],
                              SOAP_ERROR_CONNECTION: [], 
                              SOAP_ERROR_CLIENT_FAILURE: [],
                              SOAP_ERROR_UNKNOWN: [] 
                            }

    @property
    def hasErrors(self) -> bool:
        for errorType in self.errorSummary.keys():
            # TODO: may want to add special handling for certain error types so they are ignored 
            # and not treated as validation errors.  Right now, any error is treated as failure.
            if (self.errorSummary[errorType] and len(self.errorSummary[errorType]) > 0):
                return True
        
        return False

    """
    categorize exception that was caught when attempting SOAP API to the target hostname
    and update internal error summary table
    """
    def addException(self, hostname: str, ex: Exception):
        errorType = self._categorizeSoapApiException(ex)

        if (errorType not in self.errorSummary):
            self.errorSummary[errorType] = []

        self.errorSummary[errorType].append(hostname)

    """
    parse validation errors table and return as a summary string (JSON) if there were validation failures,
    otherwise return None
    """
    def getValidationErrorsMessage(self) -> str:
        if self.hasErrors:
            return json.dumps(self.errorSummary, sort_keys=True, indent=None, cls=JsonEncoder)
        else:
            return None
        
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
