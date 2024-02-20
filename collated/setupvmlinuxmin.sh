#!/bin/bash -e

abort()
{
    echo >&2 '
***************
*** ABORTED ***
***************
'
    echo "An error occurred. Exiting..." >&2
    exit 1
}

trap 'abort' 0

set -e

# Add your script below....
# If an error occurs, the abort() function will be called.
#----------------------------------------------------------
# ===> Your script goes here
# Install Azure CLI (instructions taken from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
curl -fsSL https://aka.ms/InstallAzureCLIDeb | sudo bash
echo "azure-cli https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt" >> $HELPER_SCRIPTS/apt-sources.txt
sudo rm -f /etc/apt/sources.list.d/azure-cli.list
sudo rm -f /etc/apt/sources.list.d/azure-cli.list.save

# AZURE_EXTENSION_DIR shell variable defines where modules are installed
# https://docs.microsoft.com/en-us/cli/azure/azure-cli-extensions-overview
export AZURE_EXTENSION_DIR=/opt/az/azcliextensions
echo "AZURE_EXTENSION_DIR=/opt/az/azcliextensions" | sudo tee -a /etc/environment

# install azure devops Cli extension
az extension add -n azure-devops

sudo apt-get install -y unzip

az version

# Done!
trap : 0

echo >&2 '
************
*** DONE *** 
************
'
