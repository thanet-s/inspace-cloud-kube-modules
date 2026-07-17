{{/*
Copyright 2026 Thanet S.
Licensed under the Apache License, Version 2.0.
*/}}
{{- define "inspace.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "inspace.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "inspace.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "inspace.componentName" -}}
{{- printf "%s-%s" (include "inspace.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "inspace.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "inspace.labels" -}}
helm.sh/chart: {{ include "inspace.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: inspace-cloud-kube-modules
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "inspace.componentLabels" -}}
{{ include "inspace.labels" .root }}
app.kubernetes.io/name: {{ include "inspace.componentName" . }}
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end -}}

{{- define "inspace.selectorLabels" -}}
app.kubernetes.io/name: {{ include "inspace.componentName" . }}
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end -}}

{{- define "inspace.serviceAccountName" -}}
{{- default (include "inspace.componentName" (dict "root" .root "component" .component)) .serviceAccount.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "inspace.karpenterNamespace" -}}
{{- default .Release.Namespace .Values.karpenter.namespace -}}
{{- end -}}

{{/*
Rewrite only system images owned by this chart. User-supplied repositories
outside the two explicit source namespaces are intentionally left unchanged.
*/}}
{{- define "inspace.systemImage" -}}
{{- $registry := .root.Values.global.inspace.systemImageRegistry -}}
{{- if and $registry (hasPrefix "ghcr.io/thanet-s/" .image) -}}
{{- printf "%s/%s" $registry (trimPrefix "ghcr.io/" .image) -}}
{{- else if and $registry (hasPrefix "registry.k8s.io/sig-storage/" .image) -}}
{{- printf "%s/%s" $registry (trimPrefix "registry.k8s.io/" .image) -}}
{{- else -}}
{{- .image -}}
{{- end -}}
{{- end -}}

{{- define "inspace.image" -}}
{{- $repository := include "inspace.systemImage" (dict "root" .root "image" .image.repository) -}}
{{- if .image.digest -}}
{{- printf "%s@%s" $repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repository (default .root.Chart.AppVersion .image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "inspace.validateValues" -}}
{{- if not (or .Values.ccm.enabled .Values.csi.enabled .Values.karpenter.enabled) -}}
{{- fail "at least one of ccm.enabled, csi.enabled, or karpenter.enabled must be true" -}}
{{- end -}}
{{- $controlPlaneVIP := required "global.inspace.controlPlaneVIP is required" .Values.global.inspace.controlPlaneVIP -}}
{{- $poolStart := required "global.inspace.privateLoadBalancerPool.start is required" .Values.global.inspace.privateLoadBalancerPool.start -}}
{{- $poolStop := required "global.inspace.privateLoadBalancerPool.stop is required" .Values.global.inspace.privateLoadBalancerPool.stop -}}
{{- $ipv4Pattern := `^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$` -}}
{{- range $field := list (dict "name" "controlPlaneVIP" "value" $controlPlaneVIP) (dict "name" "privateLoadBalancerPool.start" "value" $poolStart) (dict "name" "privateLoadBalancerPool.stop" "value" $poolStop) -}}
{{- if not (regexMatch $ipv4Pattern $field.value) -}}
{{- fail (printf "global.inspace.%s must be a canonical IPv4 address" $field.name) -}}
{{- end -}}
{{- $octets := splitList "." $field.value -}}
{{- $first := index $octets 0 | atoi -}}
{{- $second := index $octets 1 | atoi -}}
{{- if not (or (eq $first 10) (and (eq $first 172) (ge $second 16) (le $second 31)) (and (eq $first 192) (eq $second 168))) -}}
{{- fail (printf "global.inspace.%s must be an RFC1918 private IPv4 address" $field.name) -}}
{{- end -}}
{{- end -}}
{{- $vipOctets := splitList "." $controlPlaneVIP -}}
{{- $startOctets := splitList "." $poolStart -}}
{{- $stopOctets := splitList "." $poolStop -}}
{{- $vipValue := add (mul (index $vipOctets 0 | atoi) 16777216) (mul (index $vipOctets 1 | atoi) 65536) (mul (index $vipOctets 2 | atoi) 256) (index $vipOctets 3 | atoi) -}}
{{- $startValue := add (mul (index $startOctets 0 | atoi) 16777216) (mul (index $startOctets 1 | atoi) 65536) (mul (index $startOctets 2 | atoi) 256) (index $startOctets 3 | atoi) -}}
{{- $stopValue := add (mul (index $stopOctets 0 | atoi) 16777216) (mul (index $stopOctets 1 | atoi) 65536) (mul (index $stopOctets 2 | atoi) 256) (index $stopOctets 3 | atoi) -}}
{{- if gt $startValue $stopValue -}}
{{- fail "global.inspace.privateLoadBalancerPool.start must be less than or equal to stop" -}}
{{- end -}}
{{- $poolSize := add (sub $stopValue $startValue) 1 -}}
{{- if or (lt $poolSize 16) (gt $poolSize 256) -}}
{{- fail "global.inspace.privateLoadBalancerPool must contain between 16 and 256 addresses" -}}
{{- end -}}
{{- $podStart := add (mul 10 16777216) (mul 42 65536) -}}
{{- $podStop := add $podStart 65535 -}}
{{- $serviceStart := add (mul 10 16777216) (mul 43 65536) -}}
{{- $serviceStop := add $serviceStart 65535 -}}
{{- if or (and (le $podStart $vipValue) (le $vipValue $podStop)) (and (le $serviceStart $vipValue) (le $vipValue $serviceStop)) -}}
{{- fail "global.inspace.controlPlaneVIP must not overlap pod CIDR 10.42.0.0/16 or Service CIDR 10.43.0.0/16" -}}
{{- end -}}
{{- if or (and (le $startValue $podStop) (le $podStart $stopValue)) (and (le $startValue $serviceStop) (le $serviceStart $stopValue)) -}}
{{- fail "global.inspace.privateLoadBalancerPool must not overlap pod CIDR 10.42.0.0/16 or Service CIDR 10.43.0.0/16" -}}
{{- end -}}
{{- if and (le $startValue $vipValue) (le $vipValue $stopValue) -}}
{{- fail "global.inspace.controlPlaneVIP must be outside global.inspace.privateLoadBalancerPool" -}}
{{- end -}}
{{- if eq .Values.global.inspace.apiSecret.name "inspace-rke2-agent-token" -}}
{{- fail "global.inspace.apiSecret.name must not be the dedicated RKE2 agent-token Secret inspace-rke2-agent-token" -}}
{{- end -}}
{{- if or .Values.ccm.enabled .Values.csi.enabled .Values.karpenter.enabled -}}
{{- $networkUUID := required "global.inspace.networkUUID is required when ccm.enabled=true, csi.enabled=true, or karpenter.enabled=true" .Values.global.inspace.networkUUID -}}
{{- end -}}
{{- if .Values.ccm.enabled -}}
{{- $clusterID := required "global.inspace.clusterID is required when ccm.enabled=true" .Values.global.inspace.clusterID -}}
{{- end -}}
{{- if .Values.ccm.nodeLoadBalancer.enabled -}}
{{- if gt (len .Values.global.inspace.clusterID) 38 -}}
{{- fail "global.inspace.clusterID must be at most 38 characters when ccm.nodeLoadBalancer.enabled=true" -}}
{{- end -}}
{{- if ne .Values.karpenter.clusterName .Values.global.inspace.clusterID -}}
{{- fail "karpenter.clusterName must equal global.inspace.clusterID when ccm.nodeLoadBalancer.enabled=true" -}}
{{- end -}}
{{- if not .Values.ccm.enabled -}}
{{- fail "ccm.enabled must be true when ccm.nodeLoadBalancer.enabled=true" -}}
{{- end -}}
{{- if not .Values.karpenter.enabled -}}
{{- fail "karpenter.enabled must be true when ccm.nodeLoadBalancer.enabled=true" -}}
{{- end -}}
{{- if not .Values.karpenter.featureGates.staticCapacity -}}
{{- fail "karpenter.featureGates.staticCapacity must be true when ccm.nodeLoadBalancer.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- if .Values.karpenter.enabled -}}
{{- $clusterName := required "karpenter.clusterName is required when karpenter.enabled=true" .Values.karpenter.clusterName -}}
{{- $defaultNodeClass := required "karpenter.defaultNodeClass is required when karpenter.enabled=true" .Values.karpenter.defaultNodeClass -}}
{{- if and .Values.karpenter.agentTokenSecret.create (not .Values.karpenter.agentTokenSecret.token) -}}
{{- fail "karpenter.agentTokenSecret.token is required when karpenter.agentTokenSecret.create=true" -}}
{{- end -}}
{{- end -}}
{{- end -}}
