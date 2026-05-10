{{/*
Common helpers for EXPOSE Core chart.
*/}}

{{/* Chart name and version (truncated for label compatibility). */}}
{{- define "expose.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "expose.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "expose.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Standard labels per Kubernetes recommended labels. */}}
{{- define "expose.labels" -}}
helm.sh/chart: {{ include "expose.chart" . }}
{{ include "expose.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: expose
{{- end -}}

{{- define "expose.selectorLabels" -}}
app.kubernetes.io/name: {{ include "expose.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Service-account name. */}}
{{- define "expose.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "expose.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image reference combining global registry + image repository + tag. */}}
{{- define "expose.image" -}}
{{- $registry := .Values.global.imageRegistry | default "ghcr.io/korlogos" -}}
{{- $repo := .Values.image.repository | default "expose" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- end -}}
