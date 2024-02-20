#!/bin/bash -e

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
