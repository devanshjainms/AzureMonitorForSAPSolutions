# Python modules
import logging
import requests
import time
import random
from typing import List, Dict, Optional
from requests.exceptions import HTTPError, RetryError

# Payload modules
from helper.tools import Singleton, REST, TimeUtils

# Resource Health constants
RH_HISTORICAL_AVAILABILITY_EVENTS_ENDPOINT = "https://management.azure.com%s/providers/Microsoft.ResourceHealth/availabilityStatuses?api-version=2018-07-01&$Top=%s&$expand=recommendedactions"
MAX_RETRIES = 2
RETRY_AFTER_HEADER = 'Retry-After'
MAX_QUOTA_RESETS_AFTER = 15
RH_TIMEOUT_IN_SECONDS = 10
RH_RESPONSE_VALUE_KEY = 'value'
RH_RESPONSE_NEXT_LINK_KEY = 'next_link'


class ResourceHealth(metaclass=Singleton):
    """Singleton class that interacts with Resource Health APIs."""
    logTag = "[AIOps][ResourceHealth]"

    def __init__(self,
                 tracer: logging.Logger):
        """Constructor.

        Args:
            tracer (logging.Logger): Logger object.
        """
        self.tracer = tracer

    def getHistoricalResourceAvailabilityEvents(self, authToken: str, resourceId: str, rangeInDays: int = 1) -> List[Dict[str, str]]:
        """Get health events from RH and handle pagination.

        Args:
            authToken (str): Bearer token to be passed to RH API.
            resourceId (str): Resource Id of the resource for which the RH API should be triggered.
            rangeInDays (int, optional): Number of days for which the historical health data should be fetched. Defaults to 1.

        Returns:
            List[Dict[str, str]]: RH events.
        """
        self.tracer.info(
            "%s Getting historical availability events for the resource with Id = %s." % (self.logTag, resourceId))

        # Guard clauses.
        self.__validateInputs(authToken, resourceId, rangeInDays)
        try:
            availabilityEvents = []

            # Build RH endpoint.
            sanitizedResourceId = self.__sanitizeResourceId(resourceId)
            formattedEndpoint = RH_HISTORICAL_AVAILABILITY_EVENTS_ENDPOINT % (
                sanitizedResourceId, rangeInDays)
            self.tracer.info("%s RH endpoint = %s" %
                             (self.logTag, formattedEndpoint))

            # Trigger first RH call.
            headers = {
                "Authorization": "Bearer %s" % authToken
            }
            rhResponse = self.__triggerHistoricalResourceAvailabilityEventsAPI(
                formattedEndpoint, headers)
            self.tracer.info("%s number of events in RH response=%s; numberOfEventsCompiledSoFar=%s; resourceId=%s" % (
                self.logTag, len(rhResponse[RH_RESPONSE_VALUE_KEY]), len(availabilityEvents), resourceId))
            availabilityEvents.extend(rhResponse[RH_RESPONSE_VALUE_KEY])

            # Handle pagination.
            while RH_RESPONSE_NEXT_LINK_KEY in rhResponse:
                self.tracer.info(
                    "%s Getting the next page of events." % self.logTag)
                self.tracer.info("%s RH endpoint for the next page = %s" %
                                 (self.logTag, rhResponse[RH_RESPONSE_NEXT_LINK_KEY]))
                rhResponse = self.__triggerHistoricalResourceAvailabilityEventsAPI(
                    rhResponse[RH_RESPONSE_NEXT_LINK_KEY])
                self.tracer.info("%s number of events in RH response for the subsequent page=%s; numberOfEventsCompiledSoFar=%s; resourceId=%s" % (
                    self.logTag, len(rhResponse[RH_RESPONSE_VALUE_KEY]), len(availabilityEvents), resourceId))
                availabilityEvents.extend(rhResponse[RH_RESPONSE_VALUE_KEY])

            self.tracer.info("%s Completed RH call(s). Number of events collected for the resource with Id=%s is %s" % (
                self.logTag, resourceId, len(availabilityEvents)))

            return availabilityEvents
        except Exception as e:
            self.tracer.error("%s Error while calling RH API for resource with Id = %s. numberOfEventsCompiledSoFar=%s (%s)",
                              self.logTag, resourceId, len(availabilityEvents), e, exc_info=True)

    def __triggerHistoricalResourceAvailabilityEventsAPI(self, endpoint: str, headers: Optional[Dict[str, str]] = None) -> Dict:
        """Trigger RH API along with a retry mechanism.

        Args:
            endpoint (str): RH endpoint with the resource Id.
            headers (Optional[Dict[str, str]], optional): For the first call bearer token is passed as a header. In case of pagination, the continuation token is a part of the endpoint obtained from RH response. Defaults to None.

        Returns:
            Dict: RH response.
        """
        retries = 0
        while retries <= MAX_RETRIES:
            try:
                # Track latency of the RH call.
                latencyStartTime = time.time()

                rhResponse = REST.sendRequest(
                    self.tracer, endpoint, headers=headers, timeout=RH_TIMEOUT_IN_SECONDS)

                latency = TimeUtils.getElapsedMilliseconds(latencyStartTime)

                if rhResponse is None:
                    errorMessage = "%s Received None as the response while triggering RH API. Endpoint=%s; Latency=%s" % (
                        self.logTag, endpoint, latency)
                    raise Exception(errorMessage)
                elif RH_RESPONSE_VALUE_KEY not in rhResponse:
                    errorMessage = "%s RH response doesn't have the property %s. Response received=%s; Endpoint=%s; Latency=%s" % (
                        self.logTag, RH_RESPONSE_VALUE_KEY, rhResponse, endpoint, latency)
                    raise Exception(errorMessage)

                self.tracer.info("%s number of events in RH response=%s; endpoint=%s; latency=%s" % (
                    self.logTag, len(rhResponse[RH_RESPONSE_VALUE_KEY]), endpoint, latency))

                return rhResponse
            except HTTPError as e:
                latency = TimeUtils.getElapsedMilliseconds(latencyStartTime)

                # Check if the RH call should be retried.
                if self.__shouldRetry(e.response):
                    self.tracer.info(
                        "%s retry required for the RH call due to throttling. endpoint=%s. (%s)" % (self.logTag, endpoint, e))
                    # Wait for the throttling quota to reset.
                    self.tracer.info(
                        "%s Trying to wait for quota reset for the RH call. endpoint=%s. (%s)" % (self.logTag, endpoint))
                    self.__waitForQuotaReset(e.response)
                    retries += 1
                    continue
                # There was an unexpected HttpError. Hence rethrow.
                self.tracer.error(
                    "%s Something went wrong while triggering RH API. endpoint=%s; latency=%s. (%s)", self.logTag, endpoint, latency, e, exc_info=True)
                raise
            except Exception as e:
                latency = TimeUtils.getElapsedMilliseconds(latencyStartTime)
                self.tracer.error(
                    "%s Something went wrong while triggering RH API. endpoint=%s; latency=%s. (%s)", self.logTag, endpoint, latency, e, exc_info=True)
                # Retry as this could be because the RH call timed out.
                retries += 1
                continue
        # Max number of retries exceeded. Don't raise exception as these events can be compiled in the next run. However log the retry failure.
        if retries > MAX_RETRIES:
            errorMessage = "%s Maximum number of retries exceeded for endpoint=%s (MaxRetriesConfig=%s, CurrentRetries=%s). Aborting the RH call." % (
                self.logTag, endpoint, MAX_RETRIES, retries)
            self.tracer.error(errorMessage)

    def __validateInputs(self, authToken: str, resourceId: str, rangeInDays: int):
        """Validate inputs passed to the getHistoricalResourceAvailabilityEvents method.

        Args:
            authToken (str): Bearer token to be passed to RH API.
            resourceId (str): Resource Id of the resource for which the RH API should be triggered.
            rangeInDays (int): Number of days for which the historical health data should be fetched. Defaults to 1.

        Raises:
            ValueError: if authToken is empty or resourceId is empty.
            TypeError: if rangeInDays is not of type int.
        """
        if not authToken:
            raise ValueError(
                "%s authToken argument cannot be empty." % self.logTag)

        if not resourceId:
            raise ValueError(
                "%s resourceId argument cannot be empty." % self.logTag)

        if type(rangeInDays).__name__ != 'int':
            raise TypeError(
                "%s rangeInDays argument should be of type int." % self.logTag)

    def __sanitizeResourceId(self, resourceId: str) -> str:
        """Sanitize resource Id to have one leading forward slash and no trailing forward slash.

        Args:
            resourceId (str): Input resource Id.

        Returns:
            str: Sanitized resource Id.
        """
        # resourceId should have a leading slash.
        if resourceId[0] != '/':
            resourceId = '/'+resourceId

        # If the last character is a slash, remove it.
        if resourceId[-1] == '/':
            resourceId = resourceId[:-1]

        return resourceId

    def __shouldRetry(self, response: requests.Response) -> bool:
        """Determine if the RH API call should be retried.

        Args:
            response (requests.Response): RH API call response object.

        Returns:
            bool: True if the RH call should be retried (HTTP status code= 429), else False
        """
        self.tracer.info("%s response code from RH is %s" %
                         (self.logTag, str(response.status_code)))
        if response.status_code == 429:
            return True
        return False

    def __waitForQuotaReset(self, response: requests.Response) -> None:
        """Wait for a random period to avoid bursting.

        Args:
            response (requests.Response): RH API call response object.

        Raises:
            Exception: if Retry-After header not in response or if the time to wait is more than the MAX_QUOTA_RESETS_AFTER value.
        """
        if RETRY_AFTER_HEADER not in response.headers:
            raise Exception('%s %s not in response headers.' %
                            (self.logTag, RETRY_AFTER_HEADER))

        quotaResetsAfter = int(response.headers[RETRY_AFTER_HEADER])
        # Do not wait if quotaResetsAfter is greater than the pre-configured time. Exit early.
        if quotaResetsAfter > MAX_QUOTA_RESETS_AFTER:
            errorMessage = "%s Quota will reset after %s seconds which is higher than the max wait time. Aborting the RH call." % (
                self.logTag, quotaResetsAfter)
            self.tracer.error(errorMessage)
            raise Exception(errorMessage)
        delay = random.randint(1, 3) * quotaResetsAfter
        self.tracer.info("%s waiting for %s seconds" % (self.logTag, delay))
        time.sleep(delay)
