# Python modules
import json
import logging
import os
from datetime import datetime, timedelta

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
    # hostnames = None

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
        # self.hostnames = self.providerProperties.get("hostnames", None)
        # if not self.hostnames:
        #     self.tracer.error("[%s] no hostnames specified" % self.fullName)
        #     return False
        return True

###############################################################################

class syslogProviderCheck(ProviderCheck):

    # Stores timestamp, hostname, and message of syslogs from each hostname within a certain time limit
    lastResult = []
    # Maintains state which consists of the most recent fetched log timestamp for each hostname
    state = {}

    def __init__(self,
                provider: ProviderInstance,
                **kwargs):
        return super().__init__(provider, **kwargs)

    # Read in syslogs from hostnames and update lastResult
    def _actionFetchSyslogs(self):
        # for hostname in self.providerInstance.hostnames:
        for hostname in os.listdir("/var/log/fetched_syslogs"):
            self.updateState(hostname)
            # logpath = "/var/log/{}/syslog.log".format(hostname)
            logpath = "/var/log/fetched_syslogs/{}/syslog.log".format(hostname)
            currResult = []
            lastLogDateTime = None
            try:
                with open(logpath, 'r') as logfile:
                    for line in logfile:
                        split_line = line.split(" ", 2)
                        timestamp, name, message = split_line[0], split_line[1], split_line[2]
                        curr_datetime = datetime.now()
                        log_datetime = datetime.strptime(timestamp.split("+")[0], "%Y-%m-%dT%H:%M:%S")
                        # TODO: currently testing, actual timedelta will be 1 day
                        if curr_datetime - log_datetime < timedelta(minutes=0):
                            if self.state[hostname]["lastTimestamp"] and log_datetime > self.state[hostname]["lastTimestamp"]:
                                # Ensure that log line has not already been fetched and ingested into the Log Analytics workspace
                                currResult.append((timestamp, name, message))
                                lastLogDatetime = log_datetime
                            elif not self.state[hostname]["lastTimestamp"]:
                                # If lastTimestamp is None, then safe to fetch
                                currResult.append((timestamp, name, message))
                                lastLogDatetime = log_datetime
            except:
                self.tracer.error("[%s] unable to read log file at: %s" % (self.fullName, logpath))
            if currResult:
                self.lastResult.append(currResult)
                self.state[hostname]["lastTimestamp"] = lastLogDateTime

    # Generate a JSON-encoded string of most recent syslog from hostnames
    # This string will be ingested into Log Analytics and Customer Analytics
    def generateJsonString(self) -> str:
        logData = []
        for hostname_logs in self.lastResult:
            hostnameData = []
            for line in hostname_logs:
                logItem = {}
                logItem["timestamp"] = line[0]
                logItem["hostname"] = line[1]
                logItem["message"] = line[2]
                hostnameData.append(logItem)
            logData.append(hostnameData)

        # Convert temporary dictionary into JSON string
        try:
            # Format of JSON String:
            # [
            #   [(hostname_1, datetime, message), (hostname_1, datetime, message),...],
            #   [(hostname_2, datetime, message), (hostname_2, datetime, message),...],
            #   [(hostname_3, datetime, message), (hostname_3, datetime, message),...],
            #   ...
            # ]

            resultJsonString = json.dumps(logData, sort_keys=True, indent=4, cls=JsonEncoder)
            # self.tracer.debug("[%s] resultJson=%s" % (self.fullName,
            #                                        str(resultJsonString)))
        except Exception as e:
            self.tracer.error("[%s] could not format into JSON" % (self.fullName))

        # Clear logs stored in lastResult
        self.lastResult = []

        return resultJsonString

    def updateState(self, hostname) -> bool:
        if hostname not in self.state:
            self.state[hostname] = {"lastTimestamp": None}
        return True
