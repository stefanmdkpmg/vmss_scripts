#!/bin/bash -e
################################################################################
##  File:  install.sh
##  Desc:  Helper functions for installing tools
################################################################################

download_with_retry() {
    url=$1
    download_path=$2

    if [ -z "$download_path" ]; then
        download_path="/tmp/$(basename "$url")"
    fi

    echo "Downloading package from $url to $download_path..." >&2

    interval=30
    download_start_time=$(date +%s)

    for ((retries=20; retries>0; retries--)); do
        attempt_start_time=$(date +%s)
        if http_code=$(curl -4sSLo "$download_path" "$url" -w '%{http_code}'); then
            attempt_seconds=$(($(date +%s) - attempt_start_time))
            if [ "$http_code" -eq 200 ]; then
                echo "Package downloaded in $attempt_seconds seconds" >&2
                break
            else
                echo "Received HTTP status code $http_code after $attempt_seconds seconds" >&2
            fi
        else
            attempt_seconds=$(($(date +%s) - attempt_start_time))
            echo "Package download failed in $attempt_seconds seconds" >&2
        fi

        if [ "$retries" -le 1 ]; then
            total_seconds=$(($(date +%s) - download_start_time))
            echo "Package download failed after $total_seconds seconds" >&2
            exit 1
        fi

        echo "Waiting $interval seconds before retrying (retries left: $retries)..." >&2
        sleep $interval
    done

    echo "$download_path"
}

## Use dpkg to figure out if a package has already been installed
## Example use:
## if ! IsPackageInstalled packageName; then
##     echo "packageName is not installed!"
## fi
IsPackageInstalled() {
    dpkg -S $1 &> /dev/null
}

get_toolset_value() {
    local toolset_path="/imagegeneration/installers/toolset.json"
    local query=$1

    echo "$(jq -r "$query" $toolset_path)"
}

resolve_github_release_asset_url() {
    local repo=$1
    local filter=$2
    local version=${3:-"*"}
    local allow_pre_release=${4:-false}

    page_size="100"

    json=$(curl -fsSL "https://api.github.com/repos/${repo}/releases?per_page=${page_size}")

    if [[ $allow_pre_release == "true" ]]; then
        json=$(echo $json | jq -r '.[] | select(.assets | length > 0)')
    else
        json=$(echo $json | jq -r '.[] | select((.prerelease==false) and (.assets | length > 0))')
    fi

    if [[ $version == "latest" ]]; then
        tag_name=$(echo $json | jq -r '.tag_name' | sort --unique --version-sort | egrep -v ".*-[a-z]|beta" | tail -n 1)
    elif [[ $version == *"*"* ]]; then
        tag_name=$(echo $json | jq -r '.tag_name' | sort --unique --version-sort | egrep -v ".*-[a-z]|beta" | egrep "${version}" | tail -n 1)
    else
        tag_names=$(echo $json | jq -r '.tag_name' | sort --unique --version-sort | egrep -v ".*-[a-z]|beta" | egrep "${version}")

        for element in $tag_names; do
            semver=$(echo "$element" | awk 'match($0, /[0-9]+\.[0-9]+\.[0-9]+/) {print substr($0, RSTART, RLENGTH)}')

            if [[ $semver == $version ]]; then
                tag_name=$element
            fi
        done
    fi

    download_url=$(echo $json | jq -r ". | select(.tag_name==\"${tag_name}\").assets[].browser_download_url | select(${filter})" | head -n 1)
    if [ -z "$download_url" ]; then
        echo "Failed to parse a download url for the '${tag_name}' tag using '${filter}' filter"
        exit 1
    fi

    echo $download_url
}

get_github_package_hash() {
    local repo_owner=$1
    local repo_name=$2
    local file_name=$3
    local url=$4
    local version=${5:-"latest"}
    local prerelease=${6:-false}
    local delimiter=${7:-'|'}
    local word_number=${8:-2}

    if [[ -z "$file_name" ]]; then
        echo "File name is not specified."
        exit 1
    fi

    if [[ -n "$url" ]]; then
        release_url="$url"
    else
        if [ "$version" == "latest" ]; then
            release_url="https://api.github.com/repos/${repo_owner}/${repo_name}/releases/latest"
        else
            json=$(curl -fsSL "https://api.github.com/repos/${repo_owner}/${repo_name}/releases?per_page=100")
            tags=$(echo "$json" | jq -r --arg prerelease "$prerelease" '.[] | select(.prerelease == ($prerelease | test("true"; "i"))) | .tag_name')
            tag=$(echo "$tags" | grep -o "$version")
            if [[ "$(echo "$tag" | wc -l)" -gt 1 ]]; then
                echo "Multiple tags found matching the version $version. Please specify a more specific version."
                exit 1
            fi
            if [[ -z "$tag" ]]; then
                echo "Failed to get a tag name for version $version."
                exit 1
            fi
            release_url="https://api.github.com/repos/${repo_owner}/${repo_name}/releases/tags/$tag"
        fi
    fi

    body=$(curl -fsSL "$release_url" | jq -r '.body' | tr -d '`')
    matching_line=$(echo "$body" | grep "$file_name")
    if [[ "$(echo "$matching_line" | wc -l)" -gt 1 ]]; then
        echo "Multiple lines found included the file $file_name. Please specify a more specific file name."
        exit 1
    fi
    if [[ -z "$matching_line" ]]; then
        echo "File name '$file_name' not found in release body."
        exit 1
    fi

    result=$(echo "$matching_line" | cut -d "$delimiter" -f "$word_number" | tr -d -c '[:alnum:]')
    if [[ -z "$result" ]]; then
        echo "Empty result. Check parameters delimiter and/or word_number for the matching line."
        exit 1
    fi

    echo "$result"
}

get_hash_from_remote_file() {
    local url=$1
    local keywords=("$2" "$3")
    local delimiter=${4:-' '}
    local word_number=${5:-1}

    if [[ -z "${keywords[0]}" || -z "$url" ]]; then
        echo "File name and/or URL is not specified."
        exit 1
    fi

    matching_line=$(curl -fsSL "$url" | sed 's/  */ /g' | tr -d '`')
    for keyword in "${keywords[@]}"; do
        matching_line=$(echo "$matching_line" | grep "$keyword")
    done

    if [[ "$(echo "$matching_line" | wc -l)" -gt 1 ]]; then
        echo "Multiple lines found including the words: ${keywords[*]}. Please use a more specific filter."
        exit 1
    fi

    if [[ -z "$matching_line" ]]; then
        echo "Keywords (${keywords[*]}) not found in the file with hashes."
        exit 1
    fi

    result=$(echo "$matching_line" | cut -d "$delimiter" -f "$word_number" | tr -d -c '[:alnum:]')
    if [[ ${#result} -ne 64 && ${#result} -ne 128 ]]; then
        echo "Invalid result length. Expected 64 or 128 characters. Please check delimiter and/or word_number parameters."
        echo "Result: $result"
        exit 1
    fi

    echo "$result"
}

use_checksum_comparison() {
    local file_path=$1
    local checksum=$2
    local sha_type=${3:-"256"}

    echo "Performing checksum verification"

    if [[ ! -f "$file_path" ]]; then
        echo "File not found: $file_path"
        exit 1
    fi

    local_file_hash=$(shasum --algorithm "$sha_type" "$file_path" | awk '{print $1}')

    if [[ "$local_file_hash" != "$checksum" ]]; then
        echo "Checksum verification failed. Expected hash: $checksum; Actual hash: $local_file_hash."
        exit 1
    else
        echo "Checksum verification passed"
    fi
}


################################################################################
##  File:  etc-environment.sh
##  Desc:  Helper functions for source and modify /etc/environment
################################################################################

# NB: sed expression use '%' as a delimiter in order to simplify handling
#     values containg slashes (i.e. directory path)
#     The values containing '%' will break the functions

getEtcEnvironmentVariable () {
    variable_name="$1"

    # remove `variable_name=` and possible quotes from the line
    grep "^${variable_name}=" /etc/environment | sed -E "s%^${variable_name}=\"?([^\"]+)\"?.*$%\1%"
}

addEtcEnvironmentVariable () {
    variable_name="$1"
    variable_value="$2"

    echo "${variable_name}=${variable_value}" | sudo tee -a /etc/environment
}

replaceEtcEnvironmentVariable () {
    variable_name="$1"
    variable_value="$2"

    # modify /etc/environemnt in place by replacing a string that begins with variable_name
    sudo sed -i -e "s%^${variable_name}=.*$%${variable_name}=\"${variable_value}\"%" /etc/environment
}

setEtcEnvironmentVariable () {
    variable_name="$1"
    variable_value="$2"

    if grep "^${variable_name}=" /etc/environment > /dev/null
    then
        replaceEtcEnvironmentVariable $variable_name $variable_value
    else
        addEtcEnvironmentVariable $variable_name $variable_value
    fi
}

prependEtcEnvironmentVariable () {
    variable_name="$1"
    element="$2"

    # TODO: handle the case if the variable does not exist
    existing_value=$(getEtcEnvironmentVariable "${variable_name}")
    setEtcEnvironmentVariable "${variable_name}" "${element}:${existing_value}"
}

appendEtcEnvironmentVariable () {
    variable_name="$1"
    element="$2"

    # TODO: handle the case if the variable does not exist
    existing_value=$(getEtcEnvironmentVariable "${variable_name}")
    setEtcEnvironmentVariable "${variable_name}" "${existing_value}:${element}"
}

prependEtcEnvironmentPath () {
    element="$1"

    prependEtcEnvironmentVariable PATH "${element}"
}

appendEtcEnvironmentPath () {
    element="$1"

    appendEtcEnvironmentVariable PATH "${element}"
}

# Process /etc/environment as if it were shell script with `export VAR=...` expressions
#    The PATH variable is handled specially in order to do not override the existing PATH
#    variable. The value of PATH variable read from /etc/environment is added to the end
#    of value of the exiting PATH variable exactly as it would happen with real PAM app read
#    /etc/environment
#
# TODO: there might be the others variables to be processed in the same way as "PATH" variable
#       ie MANPATH, INFOPATH, LD_*, etc. In the current implementation the values from /etc/evironments
#       replace the values of the current environment
reloadEtcEnvironment () {
    # add `export ` to every variable of /etc/environemnt except PATH and eval the result shell script
    eval $(grep -v '^PATH=' /etc/environment | sed -e 's%^%export %')
    # handle PATH specially
    etc_path=$(getEtcEnvironmentVariable PATH)
    export PATH="$PATH:$etc_path"
}

################################################################################
##  File:  os.sh
##  Desc:  Helper functions for OS releases
################################################################################

function isUbuntu20
{
    lsb_release -d | grep -q 'Ubuntu 20'
}

function isUbuntu22
{
    lsb_release -d | grep -q 'Ubuntu 22'
}

function getOSVersionLabel
{
    lsb_release -cs
}


sudo su
apt update

################################################################################
##  File:  install-python.sh
##  Desc:  Install Python 3
################################################################################

set -e
# Source the helpers for use with the script

# Install Python, Python 3, pip, pip3
apt-get install -y --no-install-recommends python3 python3-dev python3-pip python3-venv

# Install pipx
# Set pipx custom directory
export PIPX_BIN_DIR=/opt/pipx_bin
export PIPX_HOME=/opt/pipx
python3 -m pip install pipx
python3 -m pipx ensurepath
# Update /etc/environment
setEtcEnvironmentVariable "PIPX_BIN_DIR" $PIPX_BIN_DIR
setEtcEnvironmentVariable "PIPX_HOME" $PIPX_HOME
prependEtcEnvironmentPath $PIPX_BIN_DIR
# Test pipx
if ! command -v pipx; then
    echo "pipx was not installed or not found on PATH"
    exit 1
fi

# Adding this dir to PATH will make installed pip commands are immediately available.
prependEtcEnvironmentPath '$HOME/.local/bin'


################################################################################
##  File:  install-azure-cli.sh
##  Desc:  Install Azure CLI (az)
################################################################################

# Install Azure CLI (instructions taken from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
curl -fsSL https://aka.ms/InstallAzureCLIDeb | sudo bash
echo "azure-cli https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt" >> $HELPER_SCRIPTS/apt-sources.txt
rm -f /etc/apt/sources.list.d/azure-cli.list
rm -f /etc/apt/sources.list.d/azure-cli.list.save

################################################################################
##  File:  install-azure-devops-cli.sh
##  Desc:  Install Azure DevOps CLI (az devops)
################################################################################

# Source the helpers for use with the script

# AZURE_EXTENSION_DIR shell variable defines where modules are installed
# https://docs.microsoft.com/en-us/cli/azure/azure-cli-extensions-overview
export AZURE_EXTENSION_DIR=/opt/az/azcliextensions
esetEtcEnvironmentVariable "AZURE_EXTENSION_DIR" "${AZURE_EXTENSION_DIR}"

# install azure devops Cli extension
az extension add -n azure-devops

