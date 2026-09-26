package bootstrap

// ubuntuAPTSourcesTemplate is rendered on the node: @UBUNTU_CODENAME@ becomes
// the booted release so one bootstrap serves Ubuntu 24.04 and 26.04.
const ubuntuAPTSourcesTemplate = `Types: deb
URIs: mirror+file:/etc/apt/mirrors/inspace-ubuntu.list
Suites: @UBUNTU_CODENAME@ @UBUNTU_CODENAME@-updates @UBUNTU_CODENAME@-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: mirror+file:/etc/apt/mirrors/inspace-ubuntu.list
Suites: @UBUNTU_CODENAME@-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
`

// ubuntuSourcesInstallCommands installs the APT sources for the booted Ubuntu
// release. Only the audited releases are accepted.
func ubuntuSourcesInstallCommands() string {
	return `ubuntu_codename=$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")
case "$ubuntu_codename" in
  noble|resolute) ;;
  *)
    echo "unsupported Ubuntu release codename: $ubuntu_codename" >&2
    exit 1
    ;;
esac
sed "s/@UBUNTU_CODENAME@/$ubuntu_codename/g" /var/lib/inspace/ubuntu.sources >/etc/apt/sources.list.d/ubuntu.sources
chmod 0644 /etc/apt/sources.list.d/ubuntu.sources
! grep -Fq '@UBUNTU_CODENAME@' /etc/apt/sources.list.d/ubuntu.sources
`
}

// bashLoginShellCommands makes bash the login shell of root and every regular
// account, and the default for accounts created later. Recent InSpace images
// create the SSH user with /bin/sh, which breaks bash-syntax sessions.
func bashLoginShellCommands() string {
	return `test -x /bin/bash
for login_account in $(awk -F: '($3 == 0 || ($3 >= 1000 && $3 < 65534)) && $7 ~ /^(\/usr)?\/bin\/(sh|dash)$/ { print $1 }' /etc/passwd); do
  usermod --shell /bin/bash "$login_account"
done
touch /etc/default/useradd
if grep -Eq '^#?[[:space:]]*SHELL=' /etc/default/useradd; then
  sed -Ei 's|^#?[[:space:]]*SHELL=.*|SHELL=/bin/bash|' /etc/default/useradd
else
  printf 'SHELL=/bin/bash\n' >>/etc/default/useradd
fi
if [ -f /etc/adduser.conf ]; then
  sed -Ei 's|^#?[[:space:]]*DSHELL=.*|DSHELL=/bin/bash|' /etc/adduser.conf
fi
! awk -F: '($3 == 0 || ($3 >= 1000 && $3 < 65534)) && $7 ~ /^(\/usr)?\/bin\/(sh|dash)$/' /etc/passwd | grep -q .
`
}
