# Python modules
import logging
from datetime import datetime, timedelta, timezone
from time import time
import requests

# Payload modules
from helper.tools import *
from netweaver.metricclientfactory import ServerTimeClientBase

# Suppress SSLError warning due to missing SAP server certificate
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

########
# implementation for the ServerTimeClientBase abstract class, which provides API to fetch
# SAP system time (but in this case relies on Message Server HTTP response header)
########
class MessageServerHttpClient(ServerTimeClientBase):

    def __init__(self,
                 tracer: logging.Logger,
                 logTag: str,
                 sapSid: str, 
                 sapHostName: str,
                 sapSubdomain: str,
                 sapInstanceNr: str):

        if not sapSid or not sapHostName or not sapInstanceNr:
            raise Exception("%s cannot create Message Server client with empty SID, hostname or instanceNr (%s:%s:%s)" % \
                            (logTag, sapSid, sapHostName, sapInstanceNr))

        self.tracer = tracer
        self.sapSid = sapSid
        self.sapHostName = sapHostName
        self.sapSubdomain = sapSubdomain
        self.sapInstanceNr = sapInstanceNr
        self.endpoint = MessageServerHttpClient._getFullyQualifiedEndpoint(sapHostName, 
                                                                           sapSubdomain, 
                                                                           sapInstanceNr)

    ##########
    # public interface methods for ServerTimeClientBase abstract base class
    ##########
    
    """
    make HTTP request to Message Server and look for 'date' HTTP response header
    to parse the server time of the SAP system
    """
    def getServerTimestamp(self, logTag: str) -> datetime:
        logTag = "%s[%s]" % (logTag, self.sapSid)

        # default to collector VM UTC time if we are unable to reach message server
        date = datetime.utcnow()

        try:
            # We only care about the date in the response header. so we ignore the response body
            # 'Thu, 04 Mar 2021 05:02:12 GMT'
            # NOTE: we don't need to follow redirects because the redirect response itself 300-3XX
            # will have the 'date' header as well.  In some cases we were following a chain
            # of redirects that would terminate in a 404, which would not have the 'date' header
            response = requests.get(self.endpoint, allow_redirects=False)

            if ('date' not in response.headers):
                raise Exception("no 'date' response header found for message server response status:%s/%s from:%s"
                                % (response.status_code, response.reason, self.endpoint))

            date = datetime.strptime(response.headers['date'], '%a, %d %b %Y %H:%M:%S %Z')
            self.tracer.info("%s received message server %s header: %s, parsed time: %s",
                             logTag, 
                             self.endpoint, 
                             response.headers['date'],
                             date)
        except Exception as e:
            self.tracer.info("%s suppressing expected error while fetching message server time during HTTP GET request to url %s: %s ",
                             logTag, self.endpoint, e)

        return date

    ##########
    # private static helper methods
    ##########

    @staticmethod
    def _getFullyQualifiedEndpoint(hostname: str, subdomain: str, instanceNr: str) -> str:
        httpPort = MessageServerHttpClient._getMessageServerPortFromInstanceNr(instanceNr)
        fqdn = MessageServerHttpClient._getFullyQualifiedDomainName(hostname, subdomain).lower()
        return "http://%s:%s/" % (fqdn, httpPort)

    """
    create default Message Server HTTP port based on the SAP Instance Number
    """
    @staticmethod
    def _getMessageServerPortFromInstanceNr(instanceNr: str) -> str:
        instanceNr = str(instanceNr).zfill(2)
        return '81%s' % instanceNr # As per SAP documentation, default http port is of the form 81<NR>

    """
    create fully qualified domain name of format {hostname}[.{subdomain}]
    """
    @staticmethod
    def _getFullyQualifiedDomainName(hostname: str, subdomain: str) -> str:
        if subdomain:
            return hostname + "." + subdomain
        else:
            return hostname
