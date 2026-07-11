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

{{- define "inspace.image" -}}
{{- if .image.digest -}}
{{- printf "%s@%s" .image.repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" .image.repository (default .root.Chart.AppVersion .image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "inspace.validateValues" -}}
{{- if not (or .Values.ccm.enabled .Values.csi.enabled .Values.karpenter.enabled) -}}
{{- fail "at least one of ccm.enabled, csi.enabled, or karpenter.enabled must be true" -}}
{{- end -}}
{{- if eq .Values.global.inspace.apiSecret.name "inspace-k3s-agent-token" -}}
{{- fail "global.inspace.apiSecret.name must not be the dedicated K3s agent-token Secret inspace-k3s-agent-token" -}}
{{- end -}}
{{- if .Values.ccm.enabled -}}
{{- $networkUUID := required "global.inspace.networkUUID is required when ccm.enabled=true" .Values.global.inspace.networkUUID -}}
{{- $clusterID := required "global.inspace.clusterID is required when ccm.enabled=true" .Values.global.inspace.clusterID -}}
{{- end -}}
{{- if .Values.karpenter.enabled -}}
{{- $clusterName := required "karpenter.clusterName is required when karpenter.enabled=true" .Values.karpenter.clusterName -}}
{{- $defaultNodeClass := required "karpenter.defaultNodeClass is required when karpenter.enabled=true" .Values.karpenter.defaultNodeClass -}}
{{- if and .Values.karpenter.agentTokenSecret.create (not .Values.karpenter.agentTokenSecret.token) -}}
{{- fail "karpenter.agentTokenSecret.token is required when karpenter.agentTokenSecret.create=true" -}}
{{- end -}}
{{- end -}}
{{- end -}}
