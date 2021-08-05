# Python modules
import json
import logging
import os
import subprocess

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

# td-agent config path
TD_AGENT_CONFIG_PATH = "/etc/td-agent/td-agent.conf" 

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

        # update td-agent config
        if not self.updateConfig():
            raise Exception("Failed to update td-agent config file")
        
        # restart td-agent service
        if not self.restartTdAgent():
            raise Exception("Failed to restart td-agent service")

    # Update td-agent.conf file to send syslogs to log analytics
    def updateConfig(self) -> bool:
        try:
            with open(TD_AGENT_CONFIG_PATH, "w") as config_file:
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
        except Exception as e:
            self.tracer.error("[%s] error updating td-agent config file (%s)" % (self.fullName,
                                                                                   e))
            return False
        return True

    # Restart td-agent service so that changes to config file take effect
    def restartTdAgent(self) -> bool:
        try:
            subprocess.run(['service', 'td-agent', 'restart'])
        except Exception as e:
            self.tracer.error("[%s] error restarting td-agent service (%s)" % (self.fullName,
                                                                                   e))
            return False
        return True

    def validate(self) -> bool:
        return True

    # Access key vault to get information necessary for config file
    def parseProperties(self) -> True:
        try:
            kv = AzureKeyVault(self.tracer, KEYVAULT_NAMING_CONVENTION % self.ctx.sapmonId, self.ctx.msiClientId)
        except Exception as e:
            self.tracer.error("[%s] error accessing the KeyVault (%s)" % (self.fullName,
                                                                                   e))
            return False

        try:
            global_secret = json.loads(kv.getSecret(CONFIG_SECTION_GLOBAL, None).value)
        except Exception as e:
            self.tracer.error("[%s] error accessing the global secret inside the KeyVault (%s)" % (self.fullName,
                                                                                                     e))
            return False

        self.customerId = global_secret.get("logAnalyticsWorkspaceId", None)
        self.sharedKey = global_secret.get("logAnalyticsSharedKey", None)
        if not self.customerId or not self.sharedKey:
            self.tracer.error("[%s] customer ID and shared key not in KeyVault" % self.fullName)
            return False

        return True

###############################################################################

class syslogProviderCheck(ProviderCheck):

    def __init__(self,
                provider: ProviderInstance,
                **kwargs):

        return super().__init__(provider, **kwargs)

    def _actionRunSyslogProviderCheck(self):
        self.tracer.info("[%s] provider check successful" % self.fullName)

    def generateJsonString(self) -> str:
      return json.dumps([], sort_keys=True, indent=4, cls=JsonEncoder)

    def updateState(self):
      pass
