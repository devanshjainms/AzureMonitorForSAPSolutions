# Python modules
import json
import logging
import os
from datetime import datetime, timedelta
import subprocess
from file_read_backwards import FileReadBackwards

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

# Forwarded syslog directory path
FORWARDED_LOGS_DIR = "/var/log/forwarded_syslogs"
# Timedelta for which to get logs from (in days)
TIMEDELTA_IN_DAYS = 1

# td-agent config path
CONFIG_PATH = "/etc/td-agent/td-agent.conf" 

###############################################################################

class syslogProviderInstance(ProviderInstance):

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

        # update config
        self.updateConfig()
        # restart td-agent service
        self.restartTdAgent()

    def parseProperties(self) -> True:
        # need to access key vault
        kv = AzureKeyVault(self.tracer, KEYVAULT_NAMING_CONVENTION % self.ctx.sapmonId, self.ctx.msiClientId)
        global_secret = json.loads(kv.getSecret(CONFIG_SECTION_GLOBAL, None).value)
        self.customerId = global_secret.get("logAnalyticsWorkspaceId", None)
        self.sharedKey = global_secret.get("logAnalyticsSharedKey", None)
        return True

    def updateConfig(self) -> bool:
        with open(CONFIG_PATH, "w") as config_file:
            content = """<source>
                            @type syslog
                            port 5140
                            bind 0.0.0.0
                            tag system
                            protocol_type tcp
                        </source>

                        <match **>
                            @type azure-loganalytics
                            customer_id {}
                            shared_key {}
                            log_type SyslogFromFluent
                        </match>""".format(self.customerId, self.sharedKey)

            config_file.write(content)
        return True

    def restartTdAgent(self) -> bool:
        os.system('cmd /c "service td-agent restart"')
        return True

    def validate(self) -> bool:
        return True

###############################################################################

class syslogProviderCheck(ProviderCheck):

    # Stores timestamp, hostname, and message of syslogs from each hostname within the specified timedelta
    lastResult = []
    # Maintains state which consists of the following for each hostname:
    # - the most recent log timestamp ingested
    # - the most recent log message ingested
    # - the total number of log lines ingested into the Log Analytics workspace
    state = {}

    def __init__(self,
                provider: ProviderInstance,
                **kwargs):
        # Store docker container ID        
        result = subprocess.run(['hostname'], stdout=subprocess.PIPE)
        self.container_ID = result.stdout.decode('utf-8').replace('\n', '')

        return super().__init__(provider, **kwargs)

    # Read in syslogs and update lastResult
    def _actionFetchSyslogs(self):
        pass
        # for hostname in os.listdir(FORWARDED_LOGS_DIR):
        #     # don't fetch syslogs from docker container
        #     if hostname == self.container_ID:
        #         continue

        #     # add hostname to state dictionary if not present
        #     self.updateState(hostname)

        #     num_log_files = len([name for name in os.listdir(os.path.join(FORWARDED_LOGS_DIR, hostname))])
        #     currResult = []
        #     curr_datetime = datetime.now()  

        #     # keep track of these to update state
        #     lastLogDateTime, lastMessage = None, None
        #     # to avoid checking files we don't need to
        #     no_more_log_files_to_check = False

        #     for i in range(num_log_files):
        #         if no_more_log_files_to_check:
        #             break
        #         if i == 0:
        #             logpath = os.path.join(FORWARDED_LOGS_DIR, hostname, "syslog.log")
        #         else:
        #             logpath = os.path.join(FORWARDED_LOGS_DIR, hostname, "syslog.log.{}".format(i))
                
        #         try:
        #             with FileReadBackwards(logpath) as logfile:
        #                 for line in logfile:
        #                     # parse log line
        #                     split_line = line.split(" ", 2)
        #                     timestamp, name, message = split_line[0], split_line[1], split_line[2]
        #                     log_datetime = datetime.strptime(timestamp.split("+")[0], "%Y-%m-%dT%H:%M:%S")

        #                     # check whether log datetime is within specified timedelta of current time
        #                     if curr_datetime - log_datetime < timedelta(days=TIMEDELTA_IN_DAYS):
        #                         state_timestamp_is_none = not self.state[hostname]["lastTimestamp"]
        #                         log_line_not_ingested = self.state[hostname]["lastTimestamp"] and log_datetime > self.state[hostname]["lastTimestamp"]
                                
        #                         if log_datetime == self.state[hostname]["lastTimestamp"] and message == self.state[hostname]["lastMessage"]:
        #                             # this is the latest ingested log line, lines after this have already been ingested
        #                             # there is no need to check older log files
        #                             no_more_log_files_to_check = True
        #                             break
        #                         elif state_timestamp_is_none or log_line_not_ingested:
        #                             # log line has not already been ingested, so safe to ingest
        #                             currResult.append((timestamp, name, message))
        #                             if not lastLogDateTime or log_datetime > lastLogDateTime:
        #                                 lastLogDateTime = log_datetime
        #                                 lastMessage = message
        #                     else: 
        #                         # any other log lines we check will be older
        #                         break
        #         except:
        #             self.tracer.error("[%s] unable to read log file at: %s" % (self.fullName, logpath))

        #     if currResult:
        #         self.lastResult.append(currResult)
        #         self.state[hostname]["lastTimestamp"] = lastLogDateTime
        #         self.state[hostname]["lastMessage"] = lastMessage
        #         self.state[hostname]["linesIngested"] += len(currResult)

    # Generate a JSON-encoded string of most recent syslog from hostnames
    # This string will be ingested into Log Analytics and Customer Analytics
    def generateJsonString(self) -> str:
        logData = []
        for hostname_logs in self.lastResult:
            for line in hostname_logs:
                logItem = {}
                logItem["timestamp"] = line[0]
                logItem["hostname"] = line[1]
                logItem["message"] = line[2]
                logData.append(logItem)

        # Convert temporary dictionary into JSON string
        try:
            # Format of JSON String:
            # [
            #   {"hostname": ..., "message": ..., "timestamp": ...},
            #   {"hostname": ..., "message": ..., "timestamp": ...},
            #   {"hostname": ..., "message": ..., "timestamp": ...},
            #    ...
            # ]

            resultJsonString = json.dumps(logData, sort_keys=True, indent=4, cls=JsonEncoder)
            self.tracer.debug("[%s] resultJson=%s" % (self.fullName,
                                                   str(resultJsonString)))
        except Exception as e:
            self.tracer.error("[%s] could not format into JSON" % (self.fullName))

        # Clear logs stored in lastResult
        self.lastResult = []

        return resultJsonString

    def updateState(self, hostname) -> bool:
        if hostname not in self.state:
            self.state[hostname] = {"lastTimestamp": None, "lastMessage": None, "linesIngested": 0}
        return True
