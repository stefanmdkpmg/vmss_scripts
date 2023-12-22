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

