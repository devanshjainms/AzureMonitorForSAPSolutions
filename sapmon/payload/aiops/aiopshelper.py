# Python modules
import logging
from typing import List, Dict
import time

# Azure modules
from azure.identity import ManagedIdentityCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest

# Payload modules
from helper.context import Context
from helper.tools import Singleton
from aiops.azureresourcegraph import AzureResourceGraph

# AIOpsHelper class Constants
AIOPS_PROVIDER_TYPE = 'AIOps'
SUBSCRIPTION_ID = 'subscriptionId'
VNET_ID = 'vNetId'
QUERY_GET_VNET_BY_VM_ID = "Resources| where type =~ 'microsoft.compute/virtualmachines'| where properties.vmId == '%s' | mvexpand nic=properties.networkProfile.networkInterfaces| extend nicId = tostring(nic.id)| join kind=inner (Resources| where type =~ 'microsoft.network/networkinterfaces'| extend nicId = id| project nicId, id, ipConfigurations = properties.ipConfigurations| mvexpand ipConfigurations| project nicId, id, subnetId = tostring(ipConfigurations.properties.subnet.id)| parse kind=regex subnetId with vNetId '/subnets/' subnet | project nicId, id, vNetId, subnet) on nicId| project vNetId"
QUERY_LIST_VM_IN_VNET_BY_COMPUTER_NAME = "Resources| where type =~ 'microsoft.compute/virtualmachines'| where properties.extended.instanceView.computerName in~ (dynamic([%s]))| mvexpand nic=properties.networkProfile.networkInterfaces| extend nicId = tostring(nic.id)| join kind=inner (Resources| where type =~ 'microsoft.network/networkinterfaces'| mvexpand ipconfig=properties.ipConfigurations| extend subnetId=tostring(ipconfig.properties.subnet.id)| parse kind=regex subnetId with vNetId '/subnets/' subnet| where vNetId in~ (dynamic([%s]))| project nicId = id) on nicId| project computerName = properties.extended.instanceView.computerName, id, resourceGroup, subscriptionId, tenantId, vmId = properties.vmId, type"


class AIOpsHelper(metaclass=Singleton):
    """A singleton class which implements the helper methods to enable AIOps."""
    logTag = "[AIOps][AIOpsHelper]"

    def __init__(self,
                 tracer: logging.Logger,
                 collectorVMSubscriptionId: str,
                 collectorVMMsiClientId: str,
                 collectorVMId: str):
        """Constructor

        Args:
            tracer (logging.Logger): Logger object.
            collectorVMSubscriptionId (str): Subscription Id of the collector VM.
            collectorVMMsiClientId (str): Client Id of the managed identity assigned to the collector VM.
            collectorVMId (str): Guid assigned to a VM.
        """
        self.tracer = tracer
        self.subscriptionId = collectorVMSubscriptionId
        self.collectorVMMsiClientId = collectorVMMsiClientId
        self.collectorVMId = collectorVMId
        self.collectorVMVNetId = None
        self.authCredential = ManagedIdentityCredential(
            client_id=self.collectorVMMsiClientId)

        # Create AzureResourceGraph object.
        self.argClient = AzureResourceGraph(
            self.tracer, self.subscriptionId, self.authCredential)

    def getVMComputerNameToAzResourceIdMapping(self, computerNames: List[str], vNetIds: List[str] = None) -> List[Dict[str, str]]:
        """Get the Azure resource Id for the VMs using their computer names.

        Args:
            computerNames (List[str]): List of computer names for which the Azure resource Ids need to be fetched.
            vNetIds (List[str], optional): List of VNet Ids within which the VMs will be queried. Defaults to None. Collector VM VNet will be used in default case.

        Returns:
            List[Dict[str, str]]: List of mapping each containing the following properties: id, tenantId, subscriptionId, resourceGroup, type, vmId, computerName.
        """
        self.tracer.info("%s Fetching Azure resource Id for the VMs with computer names = %s." % (
            self.logTag, computerNames))
        self.tracer.info(
            "%s vNetIds (default=None) passed as input = %s." % (self.logTag, vNetIds))

        # Guard clauses.
        self.__validateInputs(computerNames)

        try:
            # If the vNet Ids are not passed as argument, use the collector VM vNetId.
            if vNetIds is None:
                self.tracer.info(
                    "%s vNetIds not passed as input. Fetching collector VM vNetId." % self.logTag)
                # Set the class attribute if not already set.
                if self.collectorVMVNetId is None:
                    self.collectorVMVNetId = self.__getCollectorVMVNetId()
                vNetIds = [self.collectorVMVNetId]
                self.tracer.info("%s Collector VM vNetId = %s" % (
                    self.logTag, vNetIds))

            self.tracer.info(
                "Requesting AzureResourceGraph to get the resources.")
            commaSeparatedComputerNames = self.__wrapInQuotesAndFormCsv(
                computerNames)
            commaSeparatedVNetIds = self.__wrapInQuotesAndFormCsv(vNetIds)

            formattedQuery = QUERY_LIST_VM_IN_VNET_BY_COMPUTER_NAME % (
                commaSeparatedComputerNames, commaSeparatedVNetIds)
            self.tracer.info("%s Formatted query = %s" % (
                self.logTag, formattedQuery))

            resources = self.argClient.getResources(
                [self.subscriptionId], formattedQuery)
            self.tracer.info(
                "%s VM query response received from AzureResourceGraph. Number of resources = %s" % (self.logTag, len(resources)))

            return resources
        except Exception as e:
            self.tracer.error(
                "%s Could not fetch vm to computer names mapping. Computer names=%s; vNetIds=%s; query=%s (%s)", self.logTag, computerNames, vNetIds, formattedQuery, e, exc_info=True)
            raise

    def __validateInputs(self, computerNames) -> None:
        """Validate inputs passed to getVMComputerNameToAzResourceIdMapping.

        Args:
            computerNames ([type]): List of computer names passed to getVMComputerNameToAzResourceIdMapping.

        Raises:
            ValueError: If computerNames is None or empty.
            TypeError: If computerNames is not of type list.
        """
        if computerNames is None:
            raise ValueError(
                '%s computerNames argument cannot be None.' % self.logTag)
        if type(computerNames).__name__ != 'list':
            raise TypeError(
                '%s computerNames argument should be of type list.' % self.logTag)
        if len(computerNames) == 0:
            raise ValueError(
                '%a computerNames argument should contain atleast one id.' % self.logTag)
        if None in computerNames:
            raise ValueError(
                '%a computerNames should not contain None value.' % self.logTag)

    def __wrapInQuotesAndFormCsv(self, listOfStringValues: List[str]) -> str:
        """Wrap each element of a list in single quotes and join these elements to form a comma separted string value.

        Args:
            listOfStringValues (List[str]): List containing the string values.

        Returns:
            str: CSV of the elements wrapped in single quotes.
        """
        return ', '.join(f"'{element.strip()}'" for element in listOfStringValues)

    def __getCollectorVMVNetId(self) -> str:
        """Get the VNet Id of the collector VM.

        Raises:
            Exception: If no results are returned by ARG for the collector VM Guid.

        Returns:
            str: VNet Id of the collector VM.
        """
        try:
            # Run the ARG query.
            self.tracer.info(
                "%s Requesting AzureResourceGraph to get the resources." % self.logTag)
            formattedQuery = QUERY_GET_VNET_BY_VM_ID % self.collectorVMId
            self.tracer.info("%s Formatted query = %s" % (
                self.logTag, formattedQuery))
            argResponse = self.argClient.getResources(
                [self.subscriptionId], formattedQuery)
            self.tracer.info(
                "%s VNet query response received from AzureResourceGraph= %s" % (self.logTag, argResponse))

            # Collector VM should only be a part of one vNet in the context of AMS.
            if len(argResponse) == 0:
                errorMessage = '%s Zero result was returned by ARG while trying to fetch vNetId for the collector VM with Id - %s.' % (
                    self.logTag, self.collectorVMId)
                self.tracer.error(errorMessage)
                raise Exception(errorMessage)
            # This would never be the case as a VM cannot be a part of more than one vNet. This condition is only an extra precaution.
            elif len(argResponse) > 1:
                errorMessage = '%s More than one result was returned by ARG while trying to fetch vNetId for the collector VM with Id - %s.' % (
                    self.logTag, self.collectorVMId)
                self.tracer.error(errorMessage)
                raise Exception(errorMessage)

            # Extract the first and only element.
            vNetId = argResponse[0][VNET_ID]

            return vNetId

        except Exception as e:
            self.tracer.error(
                "%s Could not extract vNet Id for the collector VM with Id = %s. (%s)", self.logTag, self.collectorVMId, e, exc_info=True)
            raise

    @staticmethod
    def isAIOpsEnabled(ctx: Context) -> bool:
        """Feature flag for AIOps.

        Args:
            ctx (Context): Context object initialized by sapmon.

        Returns:
            bool: True if AIOps is enabled, else False.
        """
        # Check if the instances list in ctx object has AIOpsProviderInstance instance.
        instancesFiltered = list(filter(
            lambda x: x.providerType == AIOPS_PROVIDER_TYPE, ctx.instances))
        if len(instancesFiltered) == 0:
            return False
        return True
