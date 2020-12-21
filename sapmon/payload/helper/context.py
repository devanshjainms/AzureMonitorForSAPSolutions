#!/usr/bin/env python3
#
#       Azure Monitor for SAP Solutions payload script
#       (deployed on collector VM)
#
#       License:        GNU General Public License (GPL)
#       (c) 2020        Microsoft Corp.
#

# Python modules
import re
import sys

# Payload modules
from helper.tracing import *

# Internal context handler
class Context(object):
   tracer = None

   globalParams = {}
   instances = []

   def __init__(self,
                tracer,
                operation: str):
      self.tracer = tracer
      self.tracer.info("initializing context")

      self.tracer.info("successfully initialized context")
