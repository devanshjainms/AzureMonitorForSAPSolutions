#!/bin/bash

# Disclaimer: AIOps for AMS is in private preview. Do not use this script without contacting the AMS team.

# Description: This script deletes the AIOps Provider.


# Function to delete AIOps provider and hence disable the feature.
delete_provider(){
    echo "Deleting AIOps provider."
    # Get the collector VM name.
    vmName=$(echo $managedResources|jq -r '.[]|select(.type=="Microsoft.Compute/virtualMachines")|.name')
    # Escape the double quotes in the list of vNetIds.
    properties='{\"vNetIds\":['"${vNetIds//\"/\\\"}"'], \"enabledProviders\":[\"SapNetweaver\"]}'
    # Format the docker command that is used to add the AIOps provider to AMS.
    commandToExecute="docker run --rm --volume /var/opt/microsoft/sapmon/state:/var/opt/microsoft/sapmon/$sapmonVersion/sapmon/state --network host mcr.microsoft.com/oss/azure/azure-monitor-for-sap-solutions:$sapmonVersion python3 /var/opt/microsoft/sapmon/$sapmonVersion/sapmon/payload/sapmon.py provider delete --name=AIOps"
    # Run the custom script extension using the command above.
    az vm extension set --subscription $subscriptionId --resource-group "$managedRg" --vm-name "$vmName" --name customScript --publisher Microsoft.Azure.Extensions --protected-settings "{\"commandToExecute\": \"${commandToExecute}\"}" --output none
    if [ $? -eq 0 ]; then
        echo "AIOps provider deleted successfully."
    else
        hasFailed=true
        echo "Failed to delete AIOps provider."
    fi
}

get_managed_rg(){
    echo "Fetching the resource group name of the managed resource group."
    # Install sapmonitor cli extension.
    az extension add --name sap-hana
    # Get AMS instance.
    monitor=$(az sapmonitor show --subscription $subscriptionId --resource-group $rgName --monitor-name $monitorName)
    # Get managed resource group for the AMS instance.
    managedRg=$(echo $monitor|jq -r '.managedResourceGroupName')
    echo "Managed RG is $managedRg."
}

get_managed_resources(){
    echo "Fetching the resources in the managed resource group."
    # Get the resources of the managed resource group.
    managedResources=$(az resource list --resource-group "$managedRg")
}

# Main section
subscriptionId=$1
rgName=$2
monitorName=$3
# sapmon release version
sapmonVersion=$4

# Global variables.
managedResources=''
managedRg=''
hasFailed=false

echo "Starting to disable AIOps feature."

# Get the name of the the managed resource group of the AMS instance and set the global variable.
get_managed_rg

# Get the resources in the managed resource group of the AMS instance and set the global variable.
get_managed_resources

# Delete the provider for AIOps.
delete_provider

if [ "$hasFailed" = true ]; then
    echo "Failed to disable AIOps feature."
else
    echo "AIOps feature disabled."
fi