{{/*
Name of the injector (defaults to "aksh-injector").
*/}}
{{- define "aksh-injector.name" -}}
{{- default "aksh-injector" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name — used for Deployment/Service/SA/ClusterRole names.
*/}}
{{- define "aksh-injector.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- default "aksh-injector" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
The namespace the injector runs in.
*/}}
{{- define "aksh-injector.namespace" -}}
{{- default "aksh-system" .Values.namespace -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "aksh-injector.labels" -}}
app.kubernetes.io/name: {{ include "aksh-injector.name" . }}
app.kubernetes.io/part-of: aksh
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
Selector labels (stable — do not add version/chart labels here).
*/}}
{{- define "aksh-injector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aksh-injector.name" . }}
{{- end -}}

{{/*
Fully-qualified injector image reference.
*/}}
{{- define "aksh-injector.image" -}}
{{- printf "%s:%s" .Values.injector.image.repository .Values.injector.image.tag -}}
{{- end -}}
