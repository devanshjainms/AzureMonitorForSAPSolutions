# Python modules
from datetime import datetime,timezone
import json
import logging
import uuid
import re
import urllib
import requests
from requests.exceptions import Timeout

# Payload modules
from const import PAYLOAD_VERSION
from helper.context import *
from helper.tools import JsonEncoder
from provider.base import ProviderInstance, ProviderCheck
from typing import Dict, List

# provider specific modules
from prometheus_client.samples import Sample
from prometheus_client.parser import text_string_to_metric_families
###############################################################################

# Default retry settings
RETRY_RETRIES = 3
RETRY_DELAY_SECS   = 1
RETRY_BACKOFF_MULTIPLIER = 2

###############################################################################

class prometheusProviderInstance(ProviderInstance):
    metricsUrl = None
    HTTP_TIMEOUT = (2, 5) # timeouts: 2s connect, 5s read

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

    def parseProperties(self):
        ### Fixme: Should this validate the url format?
        self.metricsUrl = self.providerProperties.get("prometheusUrl", None)
        if not self.metricsUrl:
            self.tracer.error("[%s] PrometheusUrl cannot be empty" % self.fullName)
            return False
        self.instance_name = self.name
        return True

    def validate(self) -> bool:
        self.tracer.info("fetching data from %s to validate connection" % self.metricsUrl)
        try:
            metricsData = self.fetch_metrics()
            if metricsData is None:
                raise Exception("Did not receive data from endpoint")
            # Try to look at the first generator value, if it is empty, use None as an indicator
            if next(text_string_to_metric_families(metricsData), None) is None:
                raise Exception("Not able to parse data from endpoint")
            return True
        except Exception as err:
            self.tracer.info("Failed to validate %s (%s)" % (self.metricsUrl, err))
        return False

    def fetch_metrics(self) -> str:
        try:
            resp = requests.get(self.metricsUrl, timeout = self.HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.text
        except Exception as err:
            self.tracer.info("Failed to fetch %s (%s)" % (self.metricsUrl, err))
            return None

    @property
    def instance(self):
        return self.instance_name

# Implements a generic prometheus collector
class prometheusProviderCheck(ProviderCheck):
    colTimeGenerated = "TimeGeneratedPrometheus"
    excludeRegex = re.compile(r"^(?:go|promhttp|process)_")
    lastResult = ([], None)

    def __init__(self,
                 provider: ProviderInstance,
                 **kwargs):
        return super().__init__(provider, **kwargs)


    def _actionFetchMetrics(self,
                            includePrefixes: str,
                            suppressIfZeroPrefixes: str = None) -> None:
        # Helper method to streamline regular expression compilation and checks
        def compile_regexp(pattern, patternName = "Pattern"):
            if pattern:
                try:
                    return re.compile(pattern)
                except re.error as e:
                    raise Exception("%s (%s) must be a valid regular expression: %s" %
                                      (patternName, e.pattern, e.msg))
            return None
        self.tracer.info("[%s] Fetching metrics" % self.fullName)
        includeRegex = compile_regexp(includePrefixes, "includePrefixes")
        suppressIfZeroRegex = compile_regexp(suppressIfZeroPrefixes, "suppressIfZeroPrefixes")
        metricsData = self.providerInstance.fetch_metrics()
        self.lastResult = (metricsData, includeRegex, suppressIfZeroRegex)
        if metricsData is None:
            raise Exception("Unable to fetch metrics")
        if not self.updateState():
            raise Exception("Failed to update state")

    # Convert last result into a JSON string (as required by Log Analytics Data Collector API)
    def generateJsonString(self) -> str:
        # The correlation_id can be used to group fields from the same metrics call
        correlation_id = str(uuid.uuid4())
        fallback_datetime = datetime.now(timezone.utc)

        def prometheusSample2Dict(sample):
            """
            Convert a prometheus metric sample to Python dictionary for serialization
            """
            TimeGenerated = fallback_datetime
            if sample.timestamp:
                TimeGenerated = datetime.fromtimestamp(sample.timestamp, tz=timezone.utc)
            sample_dict = {
                "name" : sample.name,
                "labels" : json.dumps(sample.labels, separators=(',',':'), sort_keys=True, cls=JsonEncoder),
                "value" : sample.value,
                self.colTimeGenerated: TimeGenerated,
                "instance": self.providerInstance.instance,
                "metadata": self.providerInstance.metadata,
                "correlation_id": correlation_id
            }
            return sample_dict

        def filter_prometheus_sample(sample):
            """
            Filter out samples matching suppressIfZeroRegex with value == 0
            """
            if (suppressIfZeroRegex is not None and
                    sample.value == 0 and
                    suppressIfZeroRegex.match(sample.name)):
                return False
            return True

        def filter_prometheus_metric(metric):
            """
            Filter out names based on our exclude and include lists
            """
            # Remove everything matching excludeRegex
            if self.excludeRegex.match(metric.name):
                return False

            # If includeRegex is defined, filter out everything NOT matching
            if (includeRegex is not None and
                    includeRegex.match(metric.name) is None):
                return False

            # If none of the above matched, just let the item through
            return True

        def nodestatus_from_rhel(samplename):
            #parse sample name to retrieve status
            newstatus = samplename[len("ha_cluster_pacemaker_nodes_status_"):]
            if newstatus == "on_fail":
                newstatus = "onfail"
            return newstatus

        def map_ha_cluster_pacemaker_nodes_status(sample):
            labels = sample.labels
            labels["status"] = nodestatus_from_rhel(sample.name)
            labels["node"] = labels["instname"]
            labels["type"] = "member"
            newsample = Sample("ha_cluster_pacemaker_nodes",labels,sample.value,sample.timestamp)
            return newsample

        def map_ha_cluster_pacemaker_resources_all(sample):
            startlowercase = lambda s: s[:1].lower() + s[1:] if s else ''
            labels = sample.labels

            if labels["managed"] == "1":
                labels["managed"] =  "true"
            if labels["managed"] == "0":
                labels["managed"] =  "false"
            newrole = labels["role"]
            if len(newrole) > 0:
                labels["role"]  = startlowercase(newrole)

            newsample = Sample("ha_cluster_pacemaker_resources",labels,sample.value,sample.timestamp)

            return newsample

        def map_ha_cluster_pacemaker_resources(sample):
            labels = sample.labels
            labels["status"] = sample.name[len("ha_cluster_pacemaker_resources_status_"):]
            # look for node name after colon
            parts = labels["instname"].split(':', 2)
            if len(parts) == 2:
                labels["resource"] = parts[0]
                labels["node"] = parts[1]
            else:
                labels["resource"] = labels["instname"]
                labels["node"] = labels["hostname"]
            newsample = Sample("ha_cluster_pacemaker_resources",labels,sample.value,sample.timestamp)
            return newsample

        def map_ha_cluster_pacemaker_resources_managed(sample):
            labels = sample.labels
            labels["managed"] =  "True"
            parts = labels["instname"].split(':', 2)
            if len(parts) == 2:
                labels["resource"] = parts[0]
                labels["node"] = parts[1]
            else:
                labels["resource"] = labels["instname"]
                labels["node"] = labels["hostname"]
            newsample = Sample("ha_cluster_pacemaker_resources",labels,sample.value,sample.timestamp)
            return newsample

        def map_ha_cluster_pacemaker_fail_migration(sample):
            labels = sample.labels
            if "instname" in labels:
                parts = labels["instname"].split(':', 2)
                if len(parts) == 2:
                    labels["resource"] = parts[1]
                    labels["node"] = parts[0]
                else:
                    labels["resource"] = labels["instname"]
                    labels["node"] = labels["hostname"]
                newsample = Sample(sample.name,labels,sample.value,sample.timestamp)
                return newsample;
            else:
                return sample;

        def map_ha_cluster_pacemaker_location_constraints(sample):
            newsample = Sample("ha_cluster_pacemaker_location_constraints",sample.labels,sample.value,sample.timestamp)
            return newsample;

        test_dict = {"ha_cluster_pacemaker_nodes_status_dc": map_ha_cluster_pacemaker_nodes_status,
                     "ha_cluster_pacemaker_nodes_status_online": map_ha_cluster_pacemaker_nodes_status,
                     "ha_cluster_pacemaker_nodes_status_standby": map_ha_cluster_pacemaker_nodes_status,
                     "ha_cluster_pacemaker_nodes_status_standby_on_fail": map_ha_cluster_pacemaker_nodes_status,
                     "ha_cluster_pacemaker_nodes_status_maintenance": map_ha_cluster_pacemaker_nodes_status,
                     "ha_cluster_pacemaker_nodes_status_pending": map_ha_cluster_pacemaker_nodes_status,
                     "ha_cluster_pacemaker_nodes_status_shutdown": map_ha_cluster_pacemaker_nodes_status,
                     "ha_cluster_pacemaker_nodes_status_expected_up": map_ha_cluster_pacemaker_nodes_status,
                     "ha_cluster_pacemaker_nodes_status_unclean": map_ha_cluster_pacemaker_nodes_status,
                     "ha_cluster_pacemaker_resources_all": map_ha_cluster_pacemaker_resources_all,
                     "ha_cluster_pacemaker_resources_managed": map_ha_cluster_pacemaker_resources_managed,
                     "ha_cluster_pacemaker_resources_status_active": map_ha_cluster_pacemaker_resources,
                     "ha_cluster_pacemaker_resources_status_blocked": map_ha_cluster_pacemaker_resources,
                     "ha_cluster_pacemaker_resources_status_failed": map_ha_cluster_pacemaker_resources,
                     "ha_cluster_pacemaker_resources_status_failure_ignored": map_ha_cluster_pacemaker_resources,
                     "ha_cluster_pacemaker_resources_status_orphaned": map_ha_cluster_pacemaker_resources,
                     "ha_cluster_pacemaker_fail_count": map_ha_cluster_pacemaker_fail_migration,
                     "ha_cluster_pacemaker_migration_threshold": map_ha_cluster_pacemaker_fail_migration,
                     "ha_cluster_pacemaker_location_constraints_all": map_ha_cluster_pacemaker_location_constraints

                     }

        def rhel_to_suse_metric(samples):
            new_samples = []
            for s in samples:
                mapfunc = test_dict.get(s.name)
                if mapfunc != None:
                    newsample = mapfunc(s)
                else:
                    newsample = s
                new_samples.append(newsample)
            return new_samples


        prometheusMetricsText = self.lastResult[0]
        includeRegex = self.lastResult[1]
        suppressIfZeroRegex = self.lastResult[2]
        resultSet = list()

        def isHAclusterdata(filteredsamples):
            for sample in filteredsamples:
                if sample.name.startswith("ha_cluster", 0,10) == False:
                    return False
            return True

        def isDCnodedata(filteredsamples):
            for sample in filteredsamples:
                if sample.name == "ha_cluster_pacemaker_nodes":
                    if sample.labels["status"] == "dc":
                        if sample.labels["node"] == self.providerInstance.metadata['hostname']:
                            return True
            return False


        self.tracer.info("[%s] converting result set into JSON" % self.fullName)

        try:
            allfilteredsamples = []
            if not prometheusMetricsText:
                raise ValueError("Empty result from prometheus instance %s", self.providerInstance.instance)
            for family in filter(filter_prometheus_metric,
                                 text_string_to_metric_families(prometheusMetricsText)):
                allfilteredsamples.extend(filter(filter_prometheus_sample, rhel_to_suse_metric(family.samples)))
            if isHAclusterdata(allfilteredsamples):
                if isDCnodedata(allfilteredsamples):
                    resultSet.extend(map(prometheusSample2Dict, allfilteredsamples))
                else:
                    self.tracer.info("non-dc data from [%s]" % self.providerInstance.instance_name)
            else:
                resultSet.extend(map(prometheusSample2Dict, allfilteredsamples))
        except ValueError as e:
            self.tracer.error("[%s] Could not parse prometheus metrics (%s): %s" % (self.fullName, e, prometheusMetricsText))
            resultSet.append(prometheusSample2Dict(Sample("up", dict(), 0)))
        else:
            # The up-metric is used to determine whatever valid data could be read from
            # the prometheus endpoint and is used by prometheus in a similar way
            resultSet.append(prometheusSample2Dict(Sample("up", dict(), 1)))
        resultSet.append(prometheusSample2Dict(
            Sample("sapmon",
                   {
                       "SAPMON_VERSION": PAYLOAD_VERSION,
                       "PROVIDER_INSTANCE": self.providerInstance.name
                   }, 1)))
        # Convert temporary dictionary into JSON string
        try:
            # Use a very compact json representation to limit amount of data parsed by LA
            resultJsonString = json.dumps(resultSet, sort_keys=True,
                                          separators=(',',':'),
                                          cls=JsonEncoder)
            self.tracer.debug("[%s] resultJson=%s" % (self.fullName, str(resultJsonString)[:1000]))
        except Exception as e:
            self.tracer.error("[%s] could not format logItem=%s into JSON (%s)" % (self.fullName,
                                                                                   resultSet[:50],
                                                                                   e))
        return resultJsonString

    # Update the internal state of this check (including last run times)
    def updateState(self) -> bool:
        self.tracer.info("[%s] updating internal state" % self.fullName)
        self.state["lastRunLocal"] = datetime.utcnow()
        self.tracer.info("[%s] internal state successfully updated" % self.fullName)
        return True
