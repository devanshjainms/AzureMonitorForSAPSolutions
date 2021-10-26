#!/bin/bash

# Disclaimer: AIOps for AMS is in private preview. Do not use this script without contacting the AMS team.

# Description: This script creates a custom role that gives AMS access to read the virtual machines and its associated availability data. 
# Read access to network interfaces is also a part of the role to discover the virtual machines in the virtual networks provided as an input. 
# This role is assigned to the managed identity of the AMS collector VM. 
# AIOps provider is added to AMS using the custom script extension.


# Function to create the custom AIOps reader role if it doesn't exists.
create_role(){
    echo "Checking if the $roleName already exists."
    # Get the roles with the name, AIOps Reader Role.
    currentRoles=$(az role definition list --name "$roleName")
    # Check if a role with the same name exists or not.
    currentRolesCount=$(echo $currentRoles|jq --arg roleName "$roleName" '[.[]|select(.roleName==$roleName)]|length')

    if [ $currentRolesCount -gt 0 ]
    then
        echo "$roleName already exists."
    else
        echo "$roleName doesn't exist. Creating..."
        # Format the role definition with the role name and the subscription Id. 
        roleDefinition="{\"Name\":\"$roleName\",\"IsCustom\":true,\"Description\":\"Provides read access to the resources that are required for AIOps to function.\",\"Actions\":[\"Microsoft.Compute/virtualMachines/read\",\"Microsoft.ResourceHealth/AvailabilityStatuses/read\",\"Microsoft.Network/networkInterfaces/read\"],\"NotActions\":[],\"AssignableScopes\":[\"/subscriptions/$subscriptionId\"]}"
        # Create the role using the above role definition.
        az role definition create --role-definition "$roleDefinition"

        if [ $? -eq 0 ]; then
            echo "$roleName successfully created."
        else
            hasFailed=true
            echo "Failed to create $roleName."
        fi
    fi
}

# Function to assign the AIOps reader role to Managed Identity.
assign_role(){
    # Get the key vault name.
    kvName=$(echo $managedResources|jq -r '.[]|select(.type=="Microsoft.KeyVault/vaults")|.name')
    # Get the ARM Id of the managed identity.
    msiRId=$(echo $managedResources|jq -r '.[]|select(.type=="Microsoft.ManagedIdentity/userAssignedIdentities")|.id')
    # Get the details of the managed identity.
    msi=$(az resource show --ids "$msiRId")
    # Get the principal Id of the managed identity.
    msiPrincipalId=$(echo $msi|jq -r '.|.properties|.principalId')

    echo "Assigning $roleName to the managed identity with principal Id: $msiPrincipalId"
    az role assignment create --assignee "$msiPrincipalId" --role "$roleName" --scope "/subscriptions/$subscriptionId"
    
    if [ $? -eq 0 ]; then
        echo "Role successfully assigned."
    else
        hasFailed=true
        echo "Failed to assign $roleName to the managed identity."
    fi
}

# Function to add the provider for AIOps.
add_provider(){
    echo "Adding AIOps provider."
    # Get the collector VM name.
    vmName=$(echo $managedResources|jq -r '.[]|select(.type=="Microsoft.Compute/virtualMachines")|.name')
    # Escape the double quotes in the list of vNetIds.
    properties='{\"vNetIds\":['"${vNetIds//\"/\\\"}"'], \"enabledProviders\":[\"SapNetweaver\"]}'
    # Format the docker command that is used to add the AIOps provider to AMS.
    commandToExecute="docker run --rm --volume /var/opt/microsoft/sapmon/state:/var/opt/microsoft/sapmon/$sapmonVersion/sapmon/state --network host mcr.microsoft.com/oss/azure/azure-monitor-for-sap-solutions:$sapmonVersion python3 /var/opt/microsoft/sapmon/$sapmonVersion/sapmon/payload/sapmon.py provider add --name=AIOps --type=AIOps --properties='${properties}'"
    # Run the custom script extension using the command above.
    az vm extension set --subscription $subscriptionId --resource-group "$managedRg" --vm-name "$vmName" --name customScript --publisher Microsoft.Azure.Extensions --protected-settings "{\"commandToExecute\": \"${commandToExecute}\"}" --output none
    if [ $? -eq 0 ]; then
        echo "AIOps provider added successfully."
    else
        hasFailed=true
        echo "Failed to add AIOps provider."
    fi
}

# Function to get the managed resource group name and associated virtual network.
get_managed_rg(){
    echo "Fetching the resource group name of the managed resource group."
    # Install sapmonitor cli extension.
    az extension add --name sap-hana
    # Get AMS instance.
    monitor=$(az sapmonitor show --subscription $subscriptionId --resource-group $rgName --monitor-name $monitorName)
    # Get managed resource group for the AMS instance.
    managedRg=$(echo $monitor|jq -r '.managedResourceGroupName')
    # Get the vNetId of the collector VM if no vNetIds were provided.
    if [ "$vNetIds" == '' ]; then
        echo "Configuring collector VM VNet for AIOps as vNetIds input was not passed."
        collectorVMSubnet=$(echo $monitor|jq -r '.monitorSubnet')
        collectorVMVNet="${collectorVMSubnet%%/subnets*}"
        vNetIds='"'"$collectorVMVNet"'"'
    fi    
    echo "Managed RG is $managedRg."
}

# Function to fetch the resources in the managed resource group.
get_managed_resources(){
    echo "Fetching the resources in the managed resource group."
    # Get the resources of the managed resource group.
    managedResources=$(az resource list --resource-group "$managedRg")
}

# Main section
subscriptionId=$1
rgName=$2
monitorName=$3
vNetIds=$4
# sapmon release version
sapmonVersion=$5

roleName="AIOps Reader Role"

# Global variables.
managedResources=''
managedRg=''
hasFailed=false

echo "Starting to enable AIOps feature."

# Get the name of the the managed resource group of the AMS instance and set the global variable. 
# In case vNetIds input is empty, set it as the collector VM VNet Id.
get_managed_rg

# Get the resources in the managed resource group of the AMS instance and set the global variable.
get_managed_resources

# Create the custom role.
create_role

# Assign the custom role to the managed identity.
assign_role

# Add the provider for AIOps.
add_provider

if [ "$hasFailed" = true ]; then
    echo "Failed to enable AIOps feature."
else
    echo "AIOps feature enabled."
fi