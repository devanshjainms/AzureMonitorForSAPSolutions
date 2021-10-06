# Python modules
import logging

# Payload modules
from helper.context import Context
from aiops.aiopshelper import AIOpsHelper

# AIOpsFactory class constants.
SUBSCRIPTION_ID = 'subscriptionId'
VM_ID = 'vmId'


class AIOpsHelperFactory:
    """Helper class to instantiate AIOpsHelper instance."""
    logTag = "[AIOps][AIOpsHelperFactory]"

    @staticmethod
    def getAIOpsHelper(tracer: logging.Logger,
                       ctx: Context) -> AIOpsHelper:
        """Instantiate the instance of AIOpsHelper class using the values from ctx object.

        Args:
            tracer (logging.Logger): Logger object.
            ctx (Context): Context object initialized by sapmon.

        Returns:
            AIOpsHelper: Singleton instance of AIOpsHelper class.
        """
        try:
            tracer.info("%s Creating AIOpsHelper object." %
                        AIOpsHelperFactory.logTag)
            subscriptionId = ctx.vmInstance[SUBSCRIPTION_ID]
            collectorVMMsiClientId = ctx.msiClientId
            collectorVMId = ctx.vmInstance[VM_ID]
            tracer.info("%s subscriptionId= %s collectorVMMsiClientId= %s collectorVMId= %s" % (
                AIOpsHelperFactory.logTag, subscriptionId, collectorVMMsiClientId, collectorVMId))

            return AIOpsHelper(tracer, subscriptionId, collectorVMMsiClientId, collectorVMId)
        except Exception as e:
            tracer.error(
                "%s Unexpected failure trying to create AIOpsHelper object. (%s)" % (AIOpsHelperFactory.logTag, e), exc_info=True)
            raise
