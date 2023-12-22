#!/bin/bash -e
################################################################################
##  File:  configure-apt-mock.sh
##  Desc:  A temporary workaround for https://github.com/Azure/azure-linux-extensions/issues/1238.
##         Cleaned up during configure-cleanup.sh.
################################################################################

prefix=/usr/local/bin

for real_tool in /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-fast /usr/bin/apt-key;do
  tool=`basename $real_tool`
  cat >$prefix/$tool <<EOT
#!/bin/sh

i=1
while [ \$i -le 30 ];do
  err=\$(mktemp)
  $real_tool "\$@" 2>\$err

  # no errors, break the loop and continue normal flow
  test -f \$err || break
  cat \$err >&2

  retry=false

  if grep -q 'Could not get lock' \$err;then
    # apt db locked needs retry
    retry=true
  elif grep -q 'Could not open file /var/lib/apt/lists' \$err;then
    # apt update is not completed, needs retry
    retry=true
  elif grep -q 'IPC connect call failed' \$err;then
    # the delay should help with gpg-agent not ready
    retry=true
  elif grep -q 'Temporary failure in name resolution' \$err;then
    # It looks like DNS is not updated with random generated hostname yet
    retry=true
  elif grep -q 'dpkg frontend is locked by another process' \$err;then
    # dpkg process is busy by another process
    retry=true
  fi

  rm \$err
  if [ \$retry = false ]; then
    break
  fi

  sleep 5
  echo "...retry \$i"
  i=\$((i + 1))
done
EOT
  chmod +x $prefix/$tool
done

################################################################################
##  File:  install-ms-repos.sh
##  Desc:  Install official Microsoft package repos for the distribution
################################################################################

LSB_RELEASE=$(lsb_release -rs)

# Install Microsoft repository
wget https://packages.microsoft.com/config/ubuntu/$LSB_RELEASE/packages-microsoft-prod.deb
dpkg -i packages-microsoft-prod.deb

# update
apt-get install -y apt-transport-https ca-certificates curl software-properties-common
apt-get -yq update
apt-get -yq dist-upgrade


################################################################################
##  File:  configure-apt-sources.sh
##  Desc:  Configure apt sources with failover from Azure to Ubuntu archives.
################################################################################

touch /etc/apt/apt-mirrors.txt

printf "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n" | tee -a /etc/apt/apt-mirrors.txt
printf "http://archive.ubuntu.com/ubuntu/\tpriority:2\n" | tee -a /etc/apt/apt-mirrors.txt
printf "http://security.ubuntu.com/ubuntu/\tpriority:3\n" | tee -a /etc/apt/apt-mirrors.txt

sed -i 's/http:\/\/azure.archive.ubuntu.com\/ubuntu\//mirror+file:\/etc\/apt\/apt-mirrors.txt/' /etc/apt/sources.list

cp -f /etc/apt/sources.list /etc/cloud/templates/sources.list.ubuntu.tmpl


################################################################################
##  File:  configure-apt.sh
##  Desc:  Configure apt, install jq and apt-fast packages.
################################################################################

# Stop and disable apt-daily upgrade services;
systemctl stop apt-daily.timer
systemctl disable apt-daily.timer
systemctl disable apt-daily.service
systemctl stop apt-daily-upgrade.timer
systemctl disable apt-daily-upgrade.timer
systemctl disable apt-daily-upgrade.service

# Enable retry logic for apt up to 10 times
echo "APT::Acquire::Retries \"10\";" > /etc/apt/apt.conf.d/80-retries

# Configure apt to always assume Y
echo "APT::Get::Assume-Yes \"true\";" > /etc/apt/apt.conf.d/90assumeyes

# APT understands a field called Phased-Update-Percentage which can be used to control the rollout of a new version. It is an integer between 0 and 100.
# In case you have multiple systems that you want to receive the same set of updates, 
# you can set APT::Machine-ID to a UUID such that they all phase the same, 
# or set APT::Get::Never-Include-Phased-Updates or APT::Get::Always-Include-Phased-Updates to true such that APT will never/always consider phased updates.
# apt-cache policy pkgname
echo 'APT::Get::Always-Include-Phased-Updates "true";' > /etc/apt/apt.conf.d/99-phased-updates

# Fix bad proxy and http headers settings
cat <<EOF >> /etc/apt/apt.conf.d/99bad_proxy
Acquire::http::Pipeline-Depth 0;
Acquire::http::No-Cache true;
Acquire::BrokenProxy    true;
EOF

# Uninstall unattended-upgrades
apt-get purge unattended-upgrades

echo 'APT sources'
cat /etc/apt/sources.list

apt-get update
# Install jq
apt-get install jq

# Install apt-fast using quick-install.sh
# https://github.com/ilikenwf/apt-fast
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ilikenwf/apt-fast/master/quick-install.sh)"


################################################################################
##  File:  configure-limits.sh
##  Desc:  Configure limits
################################################################################

echo 'session required pam_limits.so' >> /etc/pam.d/common-session
echo 'session required pam_limits.so' >> /etc/pam.d/common-session-noninteractive
echo 'DefaultLimitNOFILE=65536' >> /etc/systemd/system.conf
echo 'DefaultLimitSTACK=16M:infinity' >> /etc/systemd/system.conf

# Raise Number of File Descriptors
echo '* soft nofile 65536' >> /etc/security/limits.conf
echo '* hard nofile 65536' >> /etc/security/limits.conf

# Double stack size from default 8192KB
echo '* soft stack 16384' >> /etc/security/limits.conf
echo '* hard stack 16384' >> /etc/security/limits.conf

#!/bin/bash -e
################################################################################
##  File:  configure-image-data.sh
##  Desc:  Create a file with image data and documentation links
################################################################################

imagedata_file=$IMAGEDATA_FILE
image_version=$IMAGE_VERSION
image_version_major=${image_version/.*/}
image_version_minor=$(echo $image_version | cut -d "." -f 2)
os_name=$(lsb_release -ds | sed "s/ /\\\n/g")
os_version=$(lsb_release -rs)
image_label="ubuntu-${os_version}"
version_major=${os_version/.*/}
version_wo_dot=${os_version/./}
github_url="https://github.com/actions/runner-images/blob"

software_url="${github_url}/ubuntu${version_major}/${image_version_major}.${image_version_minor}/images/ubuntu/Ubuntu${version_wo_dot}-Readme.md"
releaseUrl="https://github.com/actions/runner-images/releases/tag/ubuntu${version_major}%2F${image_version_major}.${image_version_minor}"

cat <<EOF > $imagedata_file
[
  {
    "group": "Operating System",
    "detail": "${os_name}"
  },
  {
    "group": "Runner Image",
    "detail": "Image: ${image_label}\nVersion: ${image_version}\nIncluded Software: ${software_url}\nImage Release: ${releaseUrl}"
  }
]
EOF


################################################################################
##  File:  configure-environment.sh
##  Desc:  Configure system and environment
################################################################################

# Source the helpers for use with the script
source $HELPER_SCRIPTS/os.sh
source $HELPER_SCRIPTS/etc-environment.sh

# Set ImageVersion and ImageOS env variables
setEtcEnvironmentVariable "ImageVersion" "${IMAGE_VERSION}"
setEtcEnvironmentVariable "ImageOS" "${IMAGE_OS}"

# Set the ACCEPT_EULA variable to Y value to confirm your acceptance of the End-User Licensing Agreement
setEtcEnvironmentVariable "ACCEPT_EULA" "Y"

# This directory is supposed to be created in $HOME and owned by user(https://github.com/actions/runner-images/issues/491)
mkdir -p /etc/skel/.config/configstore
setEtcEnvironmentVariable "XDG_CONFIG_HOME" '$HOME/.config'

# Change waagent entries to use /mnt for swapfile
sed -i 's/ResourceDisk.Format=n/ResourceDisk.Format=y/g' /etc/waagent.conf
sed -i 's/ResourceDisk.EnableSwap=n/ResourceDisk.EnableSwap=y/g' /etc/waagent.conf
sed -i 's/ResourceDisk.SwapSizeMB=0/ResourceDisk.SwapSizeMB=4096/g' /etc/waagent.conf

# Add localhost alias to ::1 IPv6
sed -i 's/::1 ip6-localhost ip6-loopback/::1     localhost ip6-localhost ip6-loopback/g' /etc/hosts

# Prepare directory and env variable for toolcache
AGENT_TOOLSDIRECTORY=/opt/hostedtoolcache
mkdir $AGENT_TOOLSDIRECTORY
setEtcEnvironmentVariable "AGENT_TOOLSDIRECTORY" "${AGENT_TOOLSDIRECTORY}"
chmod -R 777 $AGENT_TOOLSDIRECTORY

# https://www.elastic.co/guide/en/elasticsearch/reference/current/vm-max-map-count.html
# https://www.suse.com/support/kb/doc/?id=000016692
echo 'vm.max_map_count=262144' | tee -a /etc/sysctl.conf

# https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files
echo 'fs.inotify.max_user_watches=655360' | tee -a /etc/sysctl.conf
echo 'fs.inotify.max_user_instances=1280' | tee -a /etc/sysctl.conf

# https://github.com/actions/runner-images/pull/7860
netfilter_rule='/etc/udev/rules.d/50-netfilter.rules'
rulesd="$(dirname "${netfilter_rule}")"
mkdir -p $rulesd
touch $netfilter_rule
echo 'ACTION=="add", SUBSYSTEM=="module", KERNEL=="nf_conntrack", RUN+="/usr/sbin/sysctl net.netfilter.nf_conntrack_tcp_be_liberal=1"' | tee -a $netfilter_rule

# Create symlink for tests running
chmod +x $HELPER_SCRIPTS/invoke-tests.sh
ln -s $HELPER_SCRIPTS/invoke-tests.sh /usr/local/bin/invoke_tests

# Disable motd updates metadata
sed -i 's/ENABLED=1/ENABLED=0/g' /etc/default/motd-news

if [[ -f "/etc/fwupd/daemon.conf" ]]; then
    sed -i 's/UpdateMotd=true/UpdateMotd=false/g' /etc/fwupd/daemon.conf
    systemctl mask fwupd-refresh.timer
fi

# Disable to load providers
# https://github.com/microsoft/azure-pipelines-agent/issues/3834
if isUbuntu22; then
    sed -i 's/openssl_conf = openssl_init/#openssl_conf = openssl_init/g' /etc/ssl/openssl.cnf
fi


################################################################################
##  File:  install-apt-vital.sh
##  Desc:  Install vital command line utilities
################################################################################
source $HELPER_SCRIPTS/install.sh

vital_packages=$(get_toolset_value .apt.vital_packages[])
apt-get install -y --no-install-recommends $vital_packages

#!/bin/bash -e
################################################################################
##  File:  install-powershell.sh
##  Desc:  Install PowerShell Core
################################################################################

source $HELPER_SCRIPTS/install.sh

pwshversion=$(get_toolset_value .pwsh.version)

# Install Powershell
apt-get install -y powershell=$pwshversion*


################################################################################
##  File:  install-apt-common.sh
##  Desc:  Install basic command line utilities and dev packages
################################################################################
source $HELPER_SCRIPTS/install.sh

common_packages=$(get_toolset_value .apt.common_packages[])
cmd_packages=$(get_toolset_value .apt.cmd_packages[])
for package in $common_packages $cmd_packages; do
    echo "Install $package"
    apt-get install -y --no-install-recommends $package
done

invoke_tests "Apt"


################################################################################
##  File:  install-azure-cli.sh
##  Desc:  Install Azure CLI (az)
################################################################################

# Install Azure CLI (instructions taken from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
curl -fsSL https://aka.ms/InstallAzureCLIDeb | sudo bash
echo "azure-cli https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt" >> $HELPER_SCRIPTS/apt-sources.txt
rm -f /etc/apt/sources.list.d/azure-cli.list
rm -f /etc/apt/sources.list.d/azure-cli.list.save

invoke_tests "CLI.Tools" "Azure CLI"


################################################################################
##  File:  install-azure-devops-cli.sh
##  Desc:  Install Azure DevOps CLI (az devops)
################################################################################

# Source the helpers for use with the script
source $HELPER_SCRIPTS/etc-environment.sh

# AZURE_EXTENSION_DIR shell variable defines where modules are installed
# https://docs.microsoft.com/en-us/cli/azure/azure-cli-extensions-overview
export AZURE_EXTENSION_DIR=/opt/az/azcliextensions
setEtcEnvironmentVariable "AZURE_EXTENSION_DIR" "${AZURE_EXTENSION_DIR}"

# install azure devops Cli extension
az extension add -n azure-devops

invoke_tests "CLI.Tools" "Azure DevOps CLI"


################################################################################
##  File:  install-pypy.sh
##  Desc:  Install PyPy
################################################################################

source $HELPER_SCRIPTS/install.sh

# This function installs PyPy using the specified arguments:
#   $1=PACKAGE_URL
function InstallPyPy
{
    PACKAGE_URL=$1

    PACKAGE_TAR_NAME=$(echo "$PACKAGE_URL" | awk -F/ '{print $NF}')
    PACKAGE_NAME=${PACKAGE_TAR_NAME/.tar.bz2/}

    echo "Downloading tar archive '$PACKAGE_NAME'"
    PACKAGE_TAR_TEMP_PATH=$(download_with_retry $PACKAGE_URL)

    echo "Expand '$PACKAGE_NAME' to the /tmp folder"
    tar xf "$PACKAGE_TAR_TEMP_PATH" -C /tmp

    # Get Python version
    MAJOR_VERSION=$(echo ${PACKAGE_NAME/pypy/} | cut -d. -f1)
    PYTHON_MAJOR="python$MAJOR_VERSION"

    if [ $MAJOR_VERSION != 2 ]; then
        PYPY_MAJOR="pypy$MAJOR_VERSION"
    else
        PYPY_MAJOR="pypy"
    fi

    PACKAGE_TEMP_FOLDER="/tmp/$PACKAGE_NAME"
    PYTHON_FULL_VERSION=$("$PACKAGE_TEMP_FOLDER/bin/$PYPY_MAJOR" -c "import sys;print('{}.{}.{}'.format(sys.version_info[0],sys.version_info[1],sys.version_info[2]))")
    PYPY_FULL_VERSION=$("$PACKAGE_TEMP_FOLDER/bin/$PYPY_MAJOR" -c "import sys;print('{}.{}.{}'.format(*sys.pypy_version_info[0:3]))")
    echo "Put '$PYPY_FULL_VERSION' to PYPY_VERSION file"
    echo $PYPY_FULL_VERSION > "$PACKAGE_TEMP_FOLDER/PYPY_VERSION"

    # PyPy folder structure
    PYPY_TOOLCACHE_PATH=$AGENT_TOOLSDIRECTORY/PyPy
    PYPY_TOOLCACHE_VERSION_PATH=$PYPY_TOOLCACHE_PATH/$PYTHON_FULL_VERSION
    PYPY_TOOLCACHE_VERSION_ARCH_PATH=$PYPY_TOOLCACHE_VERSION_PATH/x64

    echo "Check if PyPy hostedtoolcache folder exist..."
    if [ ! -d $PYPY_TOOLCACHE_PATH ]; then
        mkdir -p $PYPY_TOOLCACHE_PATH
    fi

    echo "Create PyPy '$PYPY_TOOLCACHE_VERSION_PATH' folder"
    mkdir $PYPY_TOOLCACHE_VERSION_PATH

    echo "Move PyPy '$PACKAGE_TEMP_FOLDER' binaries to '$PYPY_TOOLCACHE_VERSION_ARCH_PATH' folder"
    mv $PACKAGE_TEMP_FOLDER $PYPY_TOOLCACHE_VERSION_ARCH_PATH

    echo "Create additional symlinks (Required for UsePythonVersion Azure DevOps task)"
    cd $PYPY_TOOLCACHE_VERSION_ARCH_PATH/bin

    # Starting from PyPy 7.3.4 these links are already included in the package
    [ -f ./$PYTHON_MAJOR ] || ln -s $PYPY_MAJOR $PYTHON_MAJOR
    [ -f ./python ] || ln -s $PYTHON_MAJOR python

    chmod +x ./python ./$PYTHON_MAJOR

    echo "Install latest Pip"
    ./python -m ensurepip
    ./python -m pip install --ignore-installed pip

    echo "Create complete file"
    touch $PYPY_TOOLCACHE_VERSION_PATH/x64.complete

    echo "Remove '$PACKAGE_TAR_TEMP_PATH'"
    rm -f $PACKAGE_TAR_TEMP_PATH
}

# Installation PyPy
pypyVersions=$(curl -fsSL https://downloads.python.org/pypy/versions.json)
toolsetVersions=$(get_toolset_value '.toolcache[] | select(.name | contains("PyPy")) | .versions[]')

for toolsetVersion in $toolsetVersions; do
    latestMajorPyPyVersion=$(echo $pypyVersions |
        jq -r --arg toolsetVersion $toolsetVersion '.[]
        | select((.python_version | startswith($toolsetVersion)) and .stable == true).files[]
        | select(.arch == "x64" and .platform == "linux").download_url' | head -1)
    if [[ -z "$latestMajorPyPyVersion" ]]; then
        echo "Failed to get PyPy version '$toolsetVersion'"
        exit 1
    fi

    InstallPyPy $latestMajorPyPyVersion
done

chown -R "$SUDO_USER:$SUDO_USER" "$AGENT_TOOLSDIRECTORY/PyPy"


################################################################################
##  File:  install-python.sh
##  Desc:  Install Python 3
################################################################################

set -e
# Source the helpers for use with the script
source $HELPER_SCRIPTS/etc-environment.sh
source $HELPER_SCRIPTS/os.sh

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

invoke_tests "Tools" "Python"


################################################################################
##  File:  install-pipx-packages.sh
##  Desc:  Install tools via pipx
################################################################################
source $HELPER_SCRIPTS/install.sh

export PATH="$PATH:/opt/pipx_bin"

pipx_packages=$(get_toolset_value ".pipx[] .package")

for package in $pipx_packages; do
    python_version=$(get_toolset_value ".pipx[] | select(.package == \"$package\") .python")
    if [ "$python_version" != "null" ]; then
        python_path="/opt/hostedtoolcache/Python/$python_version*/x64/bin/python$python_version"
        echo "Install $package into python $python_path"
        pipx install $package --python $python_path
    else
        echo "Install $package into default python"
        pipx install $package

        # https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html
        # Install ansible into an existing ansible-core Virtual Environment
        if [[ $package == "ansible-core" ]]; then
            pipx inject $package ansible
        fi
    fi

done

invoke_tests "Common" "PipxPackages"


################################################################################
##  File:  configure-snap.sh
##  Desc:  Configure snap
################################################################################

source $HELPER_SCRIPTS/etc-environment.sh

# Update /etc/environment to include /snap/bin in PATH
# because /etc/profile.d is ignored by `--norc` shell launch option

prependEtcEnvironmentPath "/snap/bin"

# Put snapd auto refresh on hold
# as it may generate too much traffic on Canonical's snap server
# when they are rolling a new major update out.
# Hold is calculated as today's date + 60 days

# snapd is started automatically, but during image generation
# a unix socket may die, restart snapd.service (and therefore snapd.socket)
# to make sure the socket is alive.

systemctl restart snapd.socket
systemctl restart snapd
snap set system refresh.hold="$(date --date='today+60 days' +%Y-%m-%dT%H:%M:%S%:z)"


################################################################################
##  File:  cleanup.sh
##  Desc:  Perform cleanup
################################################################################

# before cleanup
before=$(df / -Pm | awk 'NR==2{print $4}')

# clears out the local repository of retrieved package files
# It removes everything but the lock file from /var/cache/apt/archives/ and /var/cache/apt/archives/partial
apt-get clean
rm -rf /tmp/*
rm -rf /root/.cache

# journalctl
if command -v journalctl; then
    journalctl --rotate
    journalctl --vacuum-time=1s
fi

# delete all .gz and rotated file
find /var/log -type f -regex ".*\.gz$" -delete
find /var/log -type f -regex ".*\.[0-9]$" -delete

# wipe log files
find /var/log/ -type f -exec cp /dev/null {} \;

# after cleanup
after=$(df / -Pm | awk 'NR==2{print $4}')

# display size
 echo "Before: $before MB"
 echo "After : $after MB"
 echo "Delta : $(($after-$before)) MB"

# delete symlink for tests running
rm -f /usr/local/bin/invoke_tests

# remove apt mock
prefix=/usr/local/bin

for tool in apt apt-get apt-fast apt-key;do
  sudo rm -f $prefix/$tool
done


################################################################################
##  File: configure-system.sh
##  Desc: Post deployment system configuration actions
################################################################################

# Source the helpers for use with the script
source $HELPER_SCRIPT_FOLDER/etc-environment.sh

mv -f /imagegeneration/post-generation /opt

echo "chmod -R 777 /opt"
chmod -R 777 /opt
echo "chmod -R 777 /usr/share"
chmod -R 777 /usr/share

chmod 755 $IMAGE_FOLDER

# Remove quotes around PATH
ENVPATH=$(grep 'PATH=' /etc/environment | head -n 1 | sed -z 's/^PATH=*//')
ENVPATH=${ENVPATH#"\""}
ENVPATH=${ENVPATH%"\""}
addEtcEnvironmentVariable "PATH" "${ENVPATH}"
echo "Updated /etc/environment: $(cat /etc/environment)"

# Сlean yarn and npm cache
if yarn --version > /dev/null
then
  yarn cache clean
fi
if npm --version
then
  npm cache clean --force
fi
