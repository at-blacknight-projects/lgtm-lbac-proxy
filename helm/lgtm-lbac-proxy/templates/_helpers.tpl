{{/*
Expand the name of the chart.
*/}}
{{- define "lgtm-lbac-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}



{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "lgtm-lbac-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "lgtm-lbac-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "lgtm-lbac-proxy.labels" -}}
helm.sh/chart: {{ include "lgtm-lbac-proxy.chart" . }}
{{ include "lgtm-lbac-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "lgtm-lbac-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lgtm-lbac-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
"true" when this release runs as a write gateway alone (ingest.enabled and ingest.only),
otherwise empty, so it can be used directly in an if.
*/}}
{{- define "lgtm-lbac-proxy.ingestOnly" -}}
{{- if and .Values.ingest .Values.ingest.enabled .Values.ingest.only }}true{{- end }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "lgtm-lbac-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "lgtm-lbac-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}