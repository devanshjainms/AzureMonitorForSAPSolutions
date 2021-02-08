#!/bin/bash
set -e

az extension add -n sap-hana 2>/dev/null

SAPMON_RG=$1
SAPMON_NAME=$2
TARGET_VNET_ID=$3

SAPMON=$(az sapmonitor show -g ${SAPMON_RG} -n ${SAPMON_NAME})
if [ $? -ne 0 ]; then
    echo "Unable to find SapMonitor"
    exit 1
fi

echo ${SAPMON} | jq

while true; do
    read -p "Is this the SapMonitor you want to update? (y/n): " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

TARGET_VNET=$(az network vnet show --ids ${TARGET_VNET_ID})
if [ $? -ne 0 ]; then
    echo "Unable to find target VNet"
    exit 1
fi

echo ${TARGET_VNET} | jq

while true; do
    read -p "Is this the VNet you want to monitor? (y/n): " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

NETWORK_INTERFACES=$(az network vnet show --ids ${TARGET_VNET_ID} --query "subnets[?ipConfigurations != null].ipConfigurations[].id" | jq '.[] | select(contains("networkInterfaces"))')
COLLECTOR_VERSION=$(echo ${SAPMON} | jq .sapMonitorCollectorVersion -r)

hostname_ip=()

for interface in $(echo "${NETWORK_INTERFACES}"); do
    interface_without_quote=$(echo ${interface} | tr -d '"')
    nic_id=$(echo ${interface_without_quote%/*/*})
    vm_hostname=$(az network nic show --ids ${nic_id} --query "virtualMachine.id" -o tsv | cut -d'/' -f9)

    if [ -z "$vm_hostname" ]
    then
        continue
    fi

    ip_configuration=$(echo ${interface_without_quote} | cut -d'/' -f11)
    private_ip=$(az network nic show --ids ${nic_id} --query "ipConfigurations[?name == '${ip_configuration}'].privateIpAddress | [0]" -o tsv)

    hostname_ip+=(${vm_hostname})
    hostname_ip+=(${private_ip})
done

echo -e "Hostname\tPrivate IP"
for((n=0;n<${#hostname_ip[@]};n=n+2)); do
     echo -e "${hostname_ip[$n]}\t${hostname_ip[$n+1]}"
done

while true; do
    read -p "Add the following to the Collector VM's host file? (y/n): " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

COMMAND_TO_EXECUTE="echo \\\""
for((n=0;n<${#hostname_ip[@]};n=n+2)); do
    COMMAND_TO_EXECUTE+="${hostname_ip[$n+1]} ${hostname_ip[$n]}\\n"
done
COMMAND_TO_EXECUTE+="\\\" >> /etc/hosts && docker restart sapmon-ver-${COLLECTOR_VERSION}"

SAPMON_ID=$(echo ${SAPMON} | jq .managedResourceGroupName -r | cut -d'-' -f3)
az vm extension set \
    --resource-group sapmon-rg-${SAPMON_ID} \
    --vm-name sapmon-vm-${SAPMON_ID} \
    --name customScript \
    --publisher Microsoft.Azure.Extensions \
    --protected-settings "{\"commandToExecute\": \"${COMMAND_TO_EXECUTE}\"}" \
    --output none