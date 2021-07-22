from __future__ import unicode_literals

import math
import sys
import os
import logging

from prometheus_client.core import (
    CollectorRegistry, CounterMetricFamily, GaugeMetricFamily,
    HistogramMetricFamily, Metric, Sample, SummaryMetricFamily,
)
from prometheus_client.exposition import generate_latest
from prometheus_client.parser import text_string_to_metric_families



class RunParser(object):

    def fetch_metrics(self):
        text_file = open("/home/ross/rhelmetrics.txt", "r")
        data = text_file.read()
        text_file.close()
        return(data)

    def test_stuff(self):
        logging.info("test stuff")
        metricsData = self.fetch_metrics()
        for fam in text_string_to_metric_families(metricsData):
            logging.info(fam)
            logging.info("")
        logging.info("test stuff worked")

    def main(self):
        logging.basicConfig( level=logging.DEBUG)
        logging.info("main")
        self.test_stuff()
        #self.test_substring()

if __name__ == '__main__':
    RunParser().main()