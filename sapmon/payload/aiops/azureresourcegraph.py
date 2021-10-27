# Python modules
import logging
from typing import List, Dict, Type
import random
import time

# Azure modules
from azure.identity import ManagedIdentityCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions, QueryResponse
from azure.core.pipeline import PipelineResponse

# Payload modules
from helper.tools import Singleton, TimeUtils

# Azure Resource Graph Constants
RESULT_FORMAT = 'objectArray'
QUOTA_REMAINING_HEADER = 'x-ms-user-quota-remaining'
QUOTA_RESETS_AFTER_HEADER = 'x-ms-user-quota-resets-after'
MAX_QUOTA_RESETS_AFTER = 15
DEFAULT_QUOTA_RESETS_AFTER = 5
MAX_RETRIES = 2

###############################################################################

# Provide access to Azure Resource Graph.


class AzureResourceGraph(metaclass=Singleton):
    """Singleton class that provides access to Azure Resource Graph using the SDK."""

    logTag = "[AIOps][ARG]"

    def __init__(self,
                 tracer: logging.Logger,
                 subscriptionId: str,
                 authCredential: ManagedIdentityCredential):
        """Constructor

        Args:
            tracer (logging.Logger): Logger object.
            subscriptionId (str): Subsctiption Id in the context of which the queries would be run.
            authCredential (ManagedIdentityCredential): Credential of the managed identity which would be used for authorization.
        """
        self.tracer = tracer
        self.subscriptionId = subscriptionId
        self.authCredential = authCredential

        # Create Azure Resource Graph client.
        self.argClient = ResourceGraphClient(
            credential=self.authCredential,
            subscription_id=self.subscriptionId
        )

    def __customResponse(self, pipelineResponse: PipelineResponse, deserializedQueryResponse: QueryResponse, *kwargs) -> QueryResponse:
        """Extract the headers specific to throttling from the ARG HTTP response and set them as properties in the deserialized response.

        Args:
            pipelineResponse (PipelineResponse): HTTP response from ARG.
            deserializedQueryResponse (QueryResponse): Deserialized response from ARG SDK.

        Returns:
            QueryResponse: Deserialized response with the following additional properties set: quotaRemaining, quotaResetsAfter, statusCode.
        """
        self.tracer.info(
            "%s Extracting throttling headers from ARG response." % self.logTag)
        quotaRemaining = None
        quotaResetsAfter = None
        statusCode = None

        try:
            if pipelineResponse is None:
                errorMessage = "%s Pipeline response received from ARG SDK is None." % self.logTag
                raise Exception(errorMessage)
            
            headers = pipelineResponse.http_response.internal_response.headers
            self.tracer.info(
                "%s Headers from ARG SDK response = %s" % (self.logTag, headers))
            statusCode = pipelineResponse.http_response.status_code
            self.tracer.info(
                "%s Status code from ARG SDK pipeline response = %s" % (self.logTag, statusCode))
            quotaRemaining = int(
                headers._store[QUOTA_REMAINING_HEADER][1])
            quotaResetsAfter = self.__getSeconds(
                headers._store[QUOTA_RESETS_AFTER_HEADER][1])
        except Exception as e:
            self.tracer.error(
                "%s Could not extract the throttling headers from ARG response. (%s)", self.logTag, e, exc_info=True)
        finally:
            # If the header couldn't be extracted, set the default value.
            if quotaResetsAfter is None:
                quotaResetsAfter = DEFAULT_QUOTA_RESETS_AFTER

        # Adding additional properties to the response which can be used to handle throttling.
        deserializedQueryResponse.quotaRemaining = quotaRemaining
        deserializedQueryResponse.quotaResetsAfter = quotaResetsAfter
        deserializedQueryResponse.statusCode = statusCode

        return deserializedQueryResponse

    # Method that wraps the ARG Resources method and handles pagination as well as throttling.
    def getResources(self, subscriptionIds: List[str], query: str) -> List[Dict[str, str]]:
        """Wrapper around the ARG resources method. Handles pagination as well as throttling.

        Args:
            subscriptionIds (List[str]): List of subscriptions within which the resources should be queried.
            query (str): The query to be executed.

        Returns:
            List[Dict[str, str]]: List of resources, each resource being a dictionary of key-value pairs.
        """
        self.tracer.info("%s Getting resources using Azure Resource Graph for subscriptionIds=%s and query=%s." % (
            self.logTag, subscriptionIds, query))
        results = []

        # Guard clauses.
        self.__validateInputs(subscriptionIds, query)

        # Get the resources
        try:
            # First call to ARG.
            totalNumberOfResources = None
            self.tracer.info(
                "%s First request to ARG for resources." % self.logTag)
            argQueryResponse = self.__triggerArgResourcesMethod(
                query, subscriptionIds)
            totalNumberOfResources = argQueryResponse.total_records
            self.tracer.info(
                "%s Number of resources received = %s. numberOfResultsCompiledSoFar=%s; totalNumberOfResourcesExpected=%s; query=%s" % (self.logTag, len(argQueryResponse.data), len(results), totalNumberOfResources, query))
            results.extend(argQueryResponse.data)

            # If there are more than one page of results, use skip token to retrieve the subsequent pages.
            while argQueryResponse.skip_token is not None:
                self.tracer.info(
                    "%s Requesting for the next page of results from ARG." % self.logTag)
                argQueryResponse = self.__triggerArgResourcesMethod(
                    query, subscriptionIds, argQueryResponse.skip_token)
                self.tracer.info(
                    "%s Number of resources received = %s. numberOfResultsCompiledSoFar=%s; totalNumberOfResourcesExpected=%s; query=%s" % (self.logTag, len(argQueryResponse.data), len(results), totalNumberOfResources, query))
                results.extend(argQueryResponse.data)

            self.tracer.info(
                "%s Completed ARG call(s). totalNumberOfResultsCompiled= %s; totalNumberOfResourcesExpected=%s; query=%s" % (self.logTag, len(results), totalNumberOfResources, query))
            return results
        except Exception as e:
            self.tracer.error(
                "%s Could not get the resources using ARG. subscription=%s; query=%s; numberOfResultsCompiledSoFar=%s; totalNumberOfResourcesExpected(None if the first call itself failed)=%s.(%s)", self.logTag, subscriptionIds, query, len(results), totalNumberOfResources, e, exc_info=True)
            raise

    def __validateInputs(self, subscriptionIds, query):
        """Validate inputs passed to getResources.

        Args:
            subscriptionIds ([type]): List of subscription Ids passed to getResources.
            query ([type]): Query passed to getResources.

        Raises:
            ValueError: If subscriptionIds is None or empty. If query is empty.
            TypeError: If subscriptionIds is not of type list.
        """
        if subscriptionIds is None:
            raise ValueError(
                '%s subscriptionIds argument cannot be None.' % self.logTag)
        if type(subscriptionIds).__name__ != 'list':
            raise TypeError(
                '%s subscriptionIds argument should be of type list.' % self.logTag)
        if len(subscriptionIds) == 0:
            raise ValueError(
                '%s subscriptionIds argument should contain atleast one id.' % self.logTag)
        if not query:
            raise ValueError(
                '%s query argument cannot be empty.' % self.logTag)

    def __triggerArgResourcesMethod(self, query: str, subscriptionIds: List[str], skipToken: str = None) -> QueryResponse:
        """Trigger ARG Resources method.

        Args:
            query (str): Query to be run.
            subscriptionIds (List[str]): List of subscriptions within which the resources should be queried.
            skipToken (str, optional): Token from last run in case of pagination. Defaults to None.

        Raises:
            Exception: Maximum number of retries is exceeded.

        Returns:
            QueryResponse: Response from ARG.
        """

        # Build the query options.
        self.tracer.info(
            "%s Entered __triggerArgResourcesMethod" % self.logTag)
        self.tracer.info("%s Building query request options." % self.logTag)
        argQueryOptions = None
        if skipToken is None:
            argQueryOptions = QueryRequestOptions(
                result_format=RESULT_FORMAT)
        else:
            argQueryOptions = QueryRequestOptions(
                result_format=RESULT_FORMAT, skip_token=skipToken)

        # Build the query request.
        self.tracer.info("%s Building ARG query request." % self.logTag)
        argQuery = QueryRequest(
            query=query,
            subscriptions=subscriptionIds,
            options=argQueryOptions
        )

        # Call the ARG method in a loop to handle throttling.
        retries = 0
        while retries <= MAX_RETRIES:
            self.tracer.info(
                "%s Invoking resources method of ARG SDK." % self.logTag)
            argQueryResponse = None
            try:
                # Track latency of the SDK call.
                latencyStartTime = time.time()

                argQueryResponse = self.argClient.resources(
                    argQuery, cls=self.__customResponse)

                latency = TimeUtils.getElapsedMilliseconds(latencyStartTime)
            except Exception as e:
                latency = TimeUtils.getElapsedMilliseconds(latencyStartTime)
                self.tracer.error("%s ARG call failed. subscription=%s; query=%s; latency=%s ms. (e)",
                                  self.logTag, subscriptionIds, query, latency, e, exc_info=True)

            if self.__shouldRetry(argQueryResponse):
                self.tracer.info(
                    "%s Throttling limit is hit or failed to extract the status code header. ARG call took %s ms. subscription=%s; query=%s;" % (self.logTag, latency, subscriptionIds, query))
                self.__waitForQuotaReset(argQueryResponse.quotaResetsAfter)
                retries += 1
                continue

            self.tracer.info("%s Throttling limit not hit. subscription=%s; query=%s;" %
                             (self.logTag, subscriptionIds, query))
            self.tracer.info(
                "%s ARG response receieved. subscription=%s; query=%s; totalNumberOfResources=%s; numberOfResourcesInCurrentPage=%s; latency=%s ms." % (self.logTag, subscriptionIds, query, argQueryResponse.total_records, argQueryResponse.count, latency))
            return argQueryResponse

        # Max number of retries exceeded.
        if retries > MAX_RETRIES:
            errorMessage = "%s Maximum number of retries exceeded (MaxRetriesConfig=%s; CurrentRetries=%s). Aborting the ARG call. subscription=%s; query=%s" % (
                self.logTag, MAX_RETRIES, retries, subscriptionIds, query)
            self.tracer.error(errorMessage)
            raise Exception(errorMessage)

    # Check if the throttling limit has been hit for ARG calls
    def __shouldRetry(self, argQueryResponse: QueryResponse) -> bool:
        """Check if the ARG call should be retried.

        Args:
            argQueryResponse (QueryResponse): Response from ARG.

        Returns:
            bool: True if the retry limit has been hit or if the status code is None.
        """
        statusCode = argQueryResponse.statusCode
        self.tracer.info("%s Status code for the ARG call = %s" %
                         (self.logTag, str(statusCode)))
        # statusCode will be None when HTTP response header extraction failed
        if statusCode is None or statusCode == 429:
            return True
        return False

    def __waitForQuotaReset(self, quotaResetsAfter: int) -> None:
        """Wait for a random period to avoid bursting based on the quotaResetsAfter param passed.

        Args:
            quotaResetsAfter (int): The time after which the throttling quota resets.

        Raises:
            Exception: If quotaResetsAfter is greater than the maximum wait time.
        """
        # Do not wait if quotaResetsAfter is greater than the pre-configured time. Exit early.
        if quotaResetsAfter > MAX_QUOTA_RESETS_AFTER:
            errorMessage = "%s Quota will reset after %s seconds which is higher than the max wait time. Aborting the ARG call." % (
                self.logTag, quotaResetsAfter)
            self.tracer.error(errorMessage)
            raise Exception(errorMessage)
        delay = random.randint(1, 3) * quotaResetsAfter
        self.tracer.info("%s waiting for %s seconds" % (self.logTag, delay))
        time.sleep(delay)

    def __getSeconds(self, strTime: str) -> int:
        """Convert quota-resets-after header value from string to number of seconds.

        Args:
            strTime (str): Time in hh:mm:ss format.

        Returns:
            int: Number of seconds.
        """
        h, m, s = strTime.split(':')
        return int(h) * 3600 + int(m) * 60 + int(s)
