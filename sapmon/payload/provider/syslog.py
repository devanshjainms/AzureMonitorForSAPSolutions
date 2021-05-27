# Python modules
import json
import logging

# Payload modules
from const import *
from helper.azure import *
from helper.context import *
from helper.tools import *
from provider.base import ProviderInstance, ProviderCheck
from typing import Dict, List

# Default retry settings
RETRY_RETRIES = 1
RETRY_DELAY_SECS = 1
RETRY_BACKOFF_MULTIPLIER = 2

###############################################################################

class syslogProviderInstance(ProviderInstance):

    # To store a list of hostnames that the collector VM is receiving syslogs from
    hostnames = None

    def __init__(self,
                tracer: logging.Logger,
                ctx: Context,
                providerInstance: Dict[str, str],
                skipContent: bool = False,
                **kwargs):

        retrySettings = {
            "retries": RETRY_RETRIES,
            "delayInSeconds": RETRY_DELAY_SECS,
            "backoffMultiplier": RETRY_BACKOFF_MULTIPLIER
        }

        super().__init__(tracer,
                       ctx,
                       providerInstance,
                       retrySettings,
                       skipContent,
                       **kwargs)

    def validate(self) -> bool:
        return True

    # Read in hostnames from properties
    def parseProperties(self) -> bool:
        self.hostnames = self.providerProperties.get("hostnames", None)
        if not self.hostnames:
            self.tracer.error("[%s] no hostnames specified" % self.fullName)
            return False
        return True

###############################################################################

class syslogProviderCheck(ProviderCheck):

    # Will store timestamp, hostname, and message of most recent syslog from each hostname
    lastResult = []

    def __init__(self,
                provider: ProviderInstance,
                **kwargs):
        return super().__init__(provider, **kwargs)

    # Read in syslogs from hostnames and update lastResult
    def _actionFetchSyslogs(self):
        for hostname in self.providerInstance.hostnames:
            logpath = "/var/log/{}/syslog.log".format(hostname)
            currResult = None
            try:
                with open(logpath, 'r') as logfile:
                    line = logfile.readlines()[-1]
                    split_line = line.split(" ", 2)
                    currResult = (split_line[0], split_line[1], split_line[2])
            except:
                self.tracer.error("[%s] unable to read log file at: %s" % (self.fullName, logpath))
            if currResult:
                self.lastResult.append(currResult)

    # Generate a JSON-encoded string of most recent syslog from hostnames
    # This string will be ingested into Log Analytics and Customer Analytics
    def generateJsonString(self) -> str:
        logData = []
        for result in self.lastResult:
            logItem = {}
            logItem["timestamp"] = result[0]
            logItem["hostname"] = result[1]
            logItem["message"] = result[2]
            logData.append(logItem)

        # Convert temporary dictionary into JSON string
        try:
            resultJsonString = json.dumps(logData, sort_keys=True, indent=4, cls=JsonEncoder)
            self.tracer.debug("[%s] resultJson=%s" % (self.fullName,
                                                   str(resultJsonString)))
        except Exception as e:
            self.tracer.error("[%s] could not format into JSON" % (self.fullName))

        # Clear logs stored in lastResult
        self.lastResult = []

        return resultJsonString

    def updateState(self):
        pass
