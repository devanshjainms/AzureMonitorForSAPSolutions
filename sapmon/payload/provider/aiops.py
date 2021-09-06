# Python modules
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime
from re import fullmatch
from markdownify import markdownify
from typing import List, Dict, Optional
import itertools

# Payload modules
from provider.base import ProviderInstance, ProviderCheck
from helper.context import *
from aiops.resourcehealth import ResourceHealth

# AIOps constants.
NUMBER_OF_RH_THREADS = 5
MAX_TIMEOUT = 30
RESOURCE_ID = 'resourceId'
ARM_ID_TEMPLATE = '/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s'
SUBSCRIPTION_ID = 'subscriptionId'
RESOURCE_GROUP_NAME = 'resourceGroupName'
NAME = 'name'

# Default retry settings. Retry is not required since the action will fail only in case RH API call fails. Next run will collect the data for the failed run as well.
RETRY_RETRIES = 1
RETRY_DELAY_SECS = 1
RETRY_BACKOFF_MULTIPLIER = 2

# State constants
ARM_MAPPING = 'azResourceConfig'
POLLING_STATE = 'pollingState'
AZ_RESOURCE_ID = 'azResourceId'
SID = 'SID'
ARM_TYPE = 'armType'
LAST_OCCURED_TIME = 'lastOccuredTime'
LAST_RUN_TIMESTAMP = 'lastRunTimestamp'

# RH constants.
ID = 'id'
OCCURED_TIME = 'occuredTime'
OCCURED_TIME_FORMAT = ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"]
MIN_DATETIME = '1000-01-01T00:00:00.000000Z'
PROPERTIES = 'properties'
AVAILABILITY_STATE = 'availabilityState'
TITLE = 'title'
REASON_TYPE = 'reasonType'
REASON_CHRONICITY = 'reasonChronicity'
REPORTED_TIME = 'reportedTime'
HEALTH_EVENT_TYPE = 'healthEventType'
HEALTH_EVENT_CAUSE = 'healthEventCause'
RECOMMENDED_ACTIONS_CONTENT = 'recommendedActionsContent'
RECOMMENDED_ACTIONS = 'recommendedActions'
ACTION = 'action'
ACTION_HTML_OPEN_TAG = '<action>'
ACTION_HTML_CLOSE_TAG = '</action>'
SUMMARY = 'summary'
TYPE = 'type'
RH_TYPE = 'rhType'
HAS_RCA = 'hasRca'
RECOMMENDED_ACTIONS_HTML_TEMPLATE = '<h2><strong>Recommended Steps</strong></h2><blockquote><ul>%s</ul></blockquote>'


class AIOpsProviderInstance(ProviderInstance):
    """Provider instance for AIOps. This provider is not available on the AMS portal. This class is only valid for Resource Health integration."""

    def __init__(self,
                 tracer: logging.Logger,
                 ctx: Context,
                 providerInstance: Dict[str, str],
                 skipContent: bool = False,
                 **kwargs):
        """Constructor.

        Args:
            tracer (logging.Logger): Logger object.
            ctx (Context): Context object initialized by sapmon.
            providerInstance (Dict[str, str]): Dictionary containing the data from key vault config.
            skipContent (bool, optional): Flag that denotes whether content (checks) should be loaded. Defaults to False.
        """
        self.vNetIds = None
        self.enabledProviders = None
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

    def parseProperties(self) -> bool:
        """Abstract method implementation to parse AIOps specific properties stored in the key vault config.

        Returns:
            bool: True if parsing is successful, else False.
        """

        # vNetIds is not a mandatory property. This property can be used if the resources are distributed across multiple vNets.
        self.vNetIds = self.providerProperties.get("vNetIds", None)

        # enabledProviders contains the provider types for which AIOps is enabled. Mandatory property.
        self.enabledProviders = self.providerProperties.get(
            "enabledProviders", None)
        if not self.enabledProviders:
            self.tracer.error(
                "[%s] enabledProviders cannot be empty in the AIOps config." % self.fullName)
            return False
        return True

    def validate(self) -> bool:
        """Implementation of abstract method. Validate the collector VM permissions to trigger RH API.

        Returns:
            bool: True if validation is successful, else False.
        """
        # Call RH for the collector VM. If the call is successful, the collector VM has been assigned the right roles.
        collectorVM = AzureInstanceMetadataService.getComputeInstance(
            self.tracer, self.name)
        collectorVMArmId = ARM_ID_TEMPLATE % (
            collectorVM[SUBSCRIPTION_ID], collectorVM[RESOURCE_GROUP_NAME], collectorVM[NAME])
        rhClient = ResourceHealth(self.tracer)
        try:
            rhEvents = rhClient.getHistoricalResourceAvailabilityEvents(
                self.ctx.authToken, collectorVMArmId)
        except Exception as e:
            self.tracer.error(
                "[%s] RH call validation failed(%s).", self.fullName, e, exc_info=True)
            return False

        return True


class AIOpsProviderCheck(ProviderCheck):
    """AIOps provider check implementation that collects the RH data."""

    def __init__(self,
                 provider: ProviderInstance,
                 **kwargs):
        """Constructor.

        Args:
            provider (ProviderInstance): AIOpsProviderInstance object.

        Returns:
            [type]: ProviderCheck object for the checks configured in content file.
        """
        self.lastResult = None
        self.pollingState = None
        self.rhClient = ResourceHealth(provider.tracer)
        return super().__init__(provider, **kwargs)

    def generateJsonString(self) -> str:
        """Abstract method implementation to generate the json string for the results to push to LA.

        Returns:
            str: Json string of the results.
        """
        try:
            if self.lastResult is not None and len(self.lastResult) != 0:
                for result in self.lastResult:
                    result['SAPMON_VERSION'] = PAYLOAD_VERSION
                    result['PROVIDER_INSTANCE'] = self.providerInstance.name
                    result['METADATA'] = self.providerInstance.metadata
            resultJsonString = json.dumps(
                self.lastResult, sort_keys=True, indent=4, cls=JsonEncoder)
            self.tracer.debug("[%s] resultJson=%s" % (self.fullName,
                                                      str(resultJsonString)))
        except Exception as e:
            self.tracer.error("[%s] Could not format lastResult=%s into JSON (%s)", self.fullName,
                              self.lastResult,
                              e, exc_info=True)
            raise
        return resultJsonString

    def updateState(self) -> bool:
        """Abstract method implementation to update the internal state.

        Returns:
            bool: True if the internal state was updated successfully, else False
        """
        try:

            self.state["lastRunLocal"] = datetime.utcnow()

            # Update pollingState which contains the details of the last record that has been pushed to LA for any resource.
            self.state[POLLING_STATE] = self.pollingState

            self.tracer.info(
                "[%s] internal state successfully updated" % self.fullName)
            return True
        except Exception as e:
            self.tracer.error(
                "[%s] Could not update interanl state. (%s)", self.fullName, e, exc_info=True)
            return False

    def _actionGetRHEvents(self):
        """Compile the Azure resources from global state and get RH events for those resources.
        """
        self.lastResult = []
        self.pollingState = self.state.get(POLLING_STATE, {})

        # Get resources for which AIOps is enabled.
        resources = self.__compileAIOpsEnabledResources()
        self.tracer.info("[%s] There are %s resources compiled for fetching RH events and they are %s" % (
            self.fullName, len(resources), resources))

        # Get an iterator for the resources. Using iterator ensures that we loop over the resources list only once while submitting to the threadpoolexecutor.
        resourcesIterator = iter(resources)

        # Initialize a threadpoolexecutor to parallelize RH calls. Using with statement to ensure clean up of threadpoolexecutor object.
        with ThreadPoolExecutor(NUMBER_OF_RH_THREADS) as executor:
            # Schedule the first N calls.  Not scheduling them all at once, to avoid consuming excessive amounts of memory.
            futures = {
                executor.submit(self.__getRHEventsAndUpdateResult, resource): resource
                for resource in itertools.islice(resourcesIterator, NUMBER_OF_RH_THREADS)
            }

            while futures:
                # Wait for a call to complete.
                completedFutures, futures = wait(
                    futures, timeout=MAX_TIMEOUT, return_when=FIRST_COMPLETED
                )

                # Schedule the next set of calls based on the number of completed calls. There shouldn't be more than NUMBER_OF_RH_THREADS calls in the pool at a time, to keep memory consumption down.
                for resource in itertools.islice(resourcesIterator, len(completedFutures)):
                    futures.add(
                        executor.submit(
                            self.__getRHEventsAndUpdateResult, resource)
                    )

        self.tracer.info("[%s] The number of health events compiled = %s" % (
            self.fullName, len(self.lastResult)))
        self.updateState()

    def __compileAIOpsEnabledResources(self) -> List[Dict[str, str]]:
        """Compile the Azure resources from the global state and create a unique list.

        Returns:
            List[Dict[str,str]]: List of unique Azure resources, each record with the parameters: armType, SID and azResourceId.
        """
        resources = []

        # Filter the instances using the providerType to get those for which AIOps is enabled. Feature enablement is at a providerType level.
        aiopsEnabledInstances = list(filter(
            lambda instance: instance.providerType in self.providerInstance.enabledProviders, self.providerInstance.ctx.instances))
        self.tracer.info("[%s] The instances for which AIOps is enabled = %s" % (
            self.fullName, aiopsEnabledInstances))
        for instance in aiopsEnabledInstances:
            # If mapping is not available, skip the current instance.
            if ARM_MAPPING not in instance.state:
                self.tracer.warning(
                    "[%s] ARM mapping not available for the provider- %s" % (self.fullName, instance.name))
                continue
            armMapping = self.__mapAzResourceConfigObject(
                instance.state[ARM_MAPPING])
            resources.extend(armMapping)

        # Remove duplicate resources that might have arised because of the resource being shared across multiple SAP instances.
        uniqueResources = self.__removeDuplicateDictsFromList(resources)

        self.tracer.info(
            "[%s] Number of Azure resources compiled=%s. Number of unique resources compiled=%s." % (self.fullName, len(resources), len(uniqueResources)))

        return uniqueResources

    def __mapAzResourceConfigObject(self, azResourceConfigObj: Dict) -> List[Dict[str, str]]:
        """Map the global Azure resource config mapping to a flat structure.

        Args:
            azResourceConfigObj (Dict): Azure resource config mapping in global state.

        Returns:
            List[Dict[str, str]]: List of resources with a flat structure each containing the parameters: armType, SID and azResourceId.
        """
        resources = []
        for armType in azResourceConfigObj:
            armResources = azResourceConfigObj[armType]

            # Flatten the structure by compiling all the resources corresponding to each ARM type.
            mappedResources = [{ARM_TYPE: armType,
                                **armResources[instance]} for instance in armResources]
            resources.extend(mappedResources)

        return resources

    def __removeDuplicateDictsFromList(self, listOfDicts: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Remoce the duplicate dictionaries from a list.

        Args:
            listOfDicts (List[Dict[str, str]]): List of dictionaries.

        Returns:
            List[Dict[str, str]]: List of unique dictionaries.
        """
        return list({frozenset(item.items()): item for item in listOfDicts}.values())

    def __getRHEventsAndUpdateResult(self, resource: Dict[str, str]) -> None:
        """Fetch health events using RH API and update the lastResult variable.

        Args:
            resource (Dict[str, str]): Record for an Azure reosurce.
        """
        # Validate the state data.
        self.__validateResourceStateEntry(resource)

        self.tracer.info("[%s] Fetching the RH events for resource = %s" % (
            self.fullName, resource[AZ_RESOURCE_ID]))

        # Extract the polling state for the current resource.
        resourcePollingState = self.pollingState.get(
            resource[AZ_RESOURCE_ID], {})

        self.tracer.info("[%s] polling state for resource with Id = %s is %s" % (
            self.fullName, resource[AZ_RESOURCE_ID], resourcePollingState))

        # Parse the minimum time. datetime.min can't be used as the year is not formatted with zero padding.
        datetimeMin = datetime.strptime(MIN_DATETIME, OCCURED_TIME_FORMAT[0])

        # Fetch the occuredTime of the last record that was pushed to LA for the given resource.
        lastOccuredTime = resourcePollingState.get(
            LAST_OCCURED_TIME, datetimeMin)
        self.tracer.info("[%s] lastOccuredTime from polling state for resource with Id = %s is %s" % (
            self.fullName, resource[AZ_RESOURCE_ID], lastOccuredTime))

        # Variable to store updated occuredTime in case new health events are obtained from RH.
        updatedLastOccuredTime = lastOccuredTime

        try:
            rhEvents = self.rhClient.getHistoricalResourceAvailabilityEvents(
                self.providerInstance.ctx.authToken, resource[AZ_RESOURCE_ID])
            self.tracer.info("[%s] number of RH events received = %s; resourceId=%s; numberOfEventsCompiledForAllResourcesSoFar=%s" % (
                self.fullName, len(rhEvents), resource[AZ_RESOURCE_ID]), len(self.lastResult))
            numberOfNewEvents = 0
            for event in rhEvents:
                currentOccuredTime = self.__parseOccuredTime(
                    event['properties'][OCCURED_TIME])

                # Update the lastOccuredTime which can be stored in the state file for the current resource.
                if currentOccuredTime > updatedLastOccuredTime:
                    updatedLastOccuredTime = currentOccuredTime

                # Check if the event has been previously processed using the occuredTime. This will occur because the health events are obtained for the last one day and the polling frequency is 15 minutes.
                if currentOccuredTime <= lastOccuredTime:
                    # Skip this event.
                    continue

                numberOfNewEvents += 1
                # Sanitize the data and add additional data related to the resource. HTML tags are converted to markdown format and action tags are removed.
                sanitizedEvent = self.__sanitizeEvent(event, resource)

                self.lastResult.extend([sanitizedEvent])

            self.tracer.info("[%s] resourceId=%s; number of RH events received = %s; numberOfNewEvents=%s; updatedLastOccuredTime=%s" % (
                self.fullName, resource[AZ_RESOURCE_ID]), len(rhEvents), numberOfNewEvents, updatedLastOccuredTime)
            # Update the values for the current resource in the shared state dictionary.
            self.pollingState[resource[AZ_RESOURCE_ID]] = {
                LAST_OCCURED_TIME: updatedLastOccuredTime, LAST_RUN_TIMESTAMP: datetime.now()}

        except Exception as e:
            self.tracer.error(
                "[%s] Failed to get RH events and update the result for the resource with azResourceId=%s. numberOfEventsCompiledForAllResourcesSoFar=%s (%s)", self.fullName, resource[AZ_RESOURCE_ID], len(self.lastResult), e, exc_info=True)

    def __parseOccuredTime(self, occuredTime: str) -> datetime:
        """Parse occuredTime string based on its format.

        Args:
            occuredTime (str): occuredTime mentioned in the RH event.

        Raises:
            ValueError: if the format is wrong.

        Returns:
            datetime: occuredTime parsed as a datetime object.
        """

        # Guard clause.
        if not occuredTime:
            raise ValueError(
                'occuredTime cannot be null or empty.')

        # There are two possible time formats observed for occuredTime, which are stored in OCCURED_TIME_FORMAT.
        for dateFormat in OCCURED_TIME_FORMAT:
            try:
                occuredTimeParsed = datetime.strptime(occuredTime, dateFormat)
            except ValueError as e:
                self.tracer.warning(
                    "[%s] occuredTime is not of the format %s. (%s)" % (self.fullName, dateFormat, e), exc_info=True)
            else:
                self.tracer.info(
                    "[%s] occuredTime is of the format %s" % (
                        self.fullName, dateFormat))
                return occuredTimeParsed

    def __validateResourceStateEntry(self, resource: Dict[str, str]):
        """Validate the sanity of the Azure resource details obtained from the global state.

        Args:
            resource (Dict[str, str]): Dictionary containing the details of the Azure resource.

        Raises:
            ValueError: if azResourceId, SID or armType are not in the dictionary.
        """
        if AZ_RESOURCE_ID not in resource:
            raise ValueError(
                '[%s] %s is not present in the armMapping.' % (
                    self.fullName, AZ_RESOURCE_ID))
        if SID not in resource:
            raise ValueError(
                '[%s] %s is not present in the armMapping.' % (self.fullName, SID))
        if ARM_TYPE not in resource:
            raise ValueError(
                '[%s] %s is not present in the armMapping.' % (self.fullName, ARM_TYPE))

    def __sanitizeEvent(self, event: Dict, resource: Dict[str, str]) -> Dict:
        """Format the RH event data to filter and flatten the structure, and convert any HTML content into markdown format.

        Args:
            event (Dict): RH event data.
            resource (Dict[str, str]): Azure resource config data.

        Returns:
            Dict: Sanitized RH event data.
        """
        hasRca = False
        recommendedActions = None
        summary = None

        sanitizedEvent = {}

        if RECOMMENDED_ACTIONS_CONTENT in event[PROPERTIES]:
            self.tracer.info("[%s] event with id=%s has RCA." %
                             (self.fullName, event[ID]))
            # recommendedActionContents is present only if the event has the RCA.
            hasRca = True

            # recommendedActionContents is in HTML format. Convert it into markdown.
            recommendedActions = markdownify(
                event[PROPERTIES][RECOMMENDED_ACTIONS_CONTENT])

            # summary is in HTML format if RCA is present.
            summary = markdownify(
                event[PROPERTIES][SUMMARY])
        elif RECOMMENDED_ACTIONS in event[PROPERTIES]:
            self.tracer.info("[%s] event with id=%s does not have RCA." %
                             (self.fullName, event[ID]))
            # recommendedActions is a list of actions in text format. Convert it into HTML format and then convert to markdown.
            htmlFormattedRecommendedActions = self.__formatToHtml(
                event[PROPERTIES][RECOMMENDED_ACTIONS])
            recommendedActions = markdownify(htmlFormattedRecommendedActions)
            summary = event[PROPERTIES][SUMMARY]

        # Add resource related data
        sanitizedEvent[AZ_RESOURCE_ID] = resource[AZ_RESOURCE_ID]
        sanitizedEvent[SID] = resource[SID]
        sanitizedEvent[ARM_TYPE] = resource[ARM_TYPE]

        # Add RH related data.
        sanitizedEvent[ID] = event[ID]
        sanitizedEvent[NAME] = event[NAME]
        sanitizedEvent[RH_TYPE] = event[TYPE]
        parsedProperties = self.__populateProperties(
            event, summary, recommendedActions, hasRca)
        sanitizedEvent = {**sanitizedEvent, **parsedProperties}

        return sanitizedEvent

    def __formatToHtml(self, recommendedActions: List[Dict[str, str]]) -> str:
        """Convert the Json array structure of recommendedActions into an HTML list.

        Args:
            recommendedActions (List[Dict[str, str]]): List of recommended actions as obtained from RH event.

        Returns:
            str: HTML string version of the json array.
        """
        recommendedSteps = []
        for action in recommendedActions:
            actionText = action[ACTION]

            # Replace the <action> and </action> tags as the action url can't be replaced since they are not absolute urls.
            actionText = actionText.replace(ACTION_HTML_OPEN_TAG, '')
            actionText = actionText.replace(ACTION_HTML_CLOSE_TAG, '')
            recommendedSteps.append(actionText)

        # Convert the list to HTML <li> format.
        actionsAsHtmlListElements = self.__convertToHtmlListElement(
            recommendedSteps)

        # Format the html template with the <li> elements.
        htmlContent = RECOMMENDED_ACTIONS_HTML_TEMPLATE % actionsAsHtmlListElements

        return htmlContent

    def __convertToHtmlListElement(self, listOfStringValues: List[str]) -> str:
        """Wrap each string element in <li> tag and join the elements.

        Args:
            listOfStringValues (List[str]): List of string elements.

        Returns:
            str: String with the elements wrapped in <li> tags.
        """
        return ''.join(f"<li>{element}</li>" for element in listOfStringValues)

    def __populateProperties(self, event: Dict, summary: str, recommendedActions: str, hasRca: bool) -> Dict[str, str]:
        """Compile the RH properties that are relevant to AMS.

        Args:
            event (Dict): RH event.
            summary (str): summary converted to mardown format if required.
            recommendedActions (str): recommendedActions converted to markdown format.
            hasRca (bool): Flag that denotes if the record contains RCA details or not.

        Returns:
            Dict[str, str]: Dictionary with all relevant properties compiled.
        """
        self.tracer.info("[%s] Formulating properties for the event with id=%s" % (
            self.fullName, event[ID]))
        properties = {}
        properties[SUMMARY] = summary
        properties[RECOMMENDED_ACTIONS] = recommendedActions
        properties[HAS_RCA] = str(hasRca)

        if AVAILABILITY_STATE in event[PROPERTIES]:
            properties[AVAILABILITY_STATE] = event[PROPERTIES][AVAILABILITY_STATE]

        if TITLE in event[PROPERTIES]:
            properties[TITLE] = event[PROPERTIES][TITLE]

        if REASON_TYPE in event[PROPERTIES]:
            properties[REASON_TYPE] = event[PROPERTIES][REASON_TYPE]

        if HEALTH_EVENT_TYPE in event[PROPERTIES]:
            properties[HEALTH_EVENT_TYPE] = event[PROPERTIES][HEALTH_EVENT_TYPE]

        if HEALTH_EVENT_CAUSE in event[PROPERTIES]:
            properties[HEALTH_EVENT_CAUSE] = event[PROPERTIES][HEALTH_EVENT_CAUSE]

        if OCCURED_TIME in event[PROPERTIES]:
            properties[OCCURED_TIME] = event[PROPERTIES][OCCURED_TIME]

        if REPORTED_TIME in event[PROPERTIES]:
            properties[REPORTED_TIME] = event[PROPERTIES][REPORTED_TIME]

        if REASON_CHRONICITY in event[PROPERTIES]:
            properties[REASON_CHRONICITY] = event[PROPERTIES][REASON_CHRONICITY]

        return properties
