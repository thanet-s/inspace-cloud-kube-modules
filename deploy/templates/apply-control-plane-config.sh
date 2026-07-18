#!/bin/sh
set -eu

source_file=/tmp/90-inspace-operator.yaml
target_file=/etc/rancher/rke2/config.yaml.d/90-inspace-operator.yaml

install -d -m 0700 /etc/rancher/rke2/config.yaml.d
if cmp -s "$source_file" "$target_file"; then
  rm -f "$source_file"
  rm -f /tmp/inspace-apply-control-plane-config.sh
  printf unchanged
  exit 0
fi

install -m 0600 "$source_file" "$target_file"
rm -f "$source_file"
rm -f /tmp/inspace-apply-control-plane-config.sh
systemctl restart rke2-server.service
printf changed
