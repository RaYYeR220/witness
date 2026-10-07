{{/*
Expand the name of the chart.
*/}}
{{- define "witness.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "witness.fullname" -}}
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
{{- define "witness.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified name of a component: (dict "ctx" $ "component" "api").
*/}}
{{- define "witness.componentName" -}}
{{- printf "%s-%s" (include "witness.fullname" .ctx) .component | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
In-cluster DNS name of a component's service, fully qualified (nginx resolves names literally).
*/}}
{{- define "witness.serviceHost" -}}
{{- printf "%s.%s.svc.%s" (include "witness.componentName" .) .ctx.Release.Namespace .ctx.Values.clusterDomain }}
{{- end }}

{{/*
Component selector labels: (dict "ctx" $ "component" "api").
*/}}
{{- define "witness.selectorLabels" -}}
app.kubernetes.io/name: {{ include "witness.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Component labels: (dict "ctx" $ "component" "api" "values" .Values.api).
*/}}
{{- define "witness.labels" -}}
helm.sh/chart: {{ include "witness.chart" .ctx }}
{{ include "witness.selectorLabels" . }}
{{- if .ctx.Chart.AppVersion }}
app.kubernetes.io/version: {{ .ctx.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
app.kubernetes.io/part-of: witness
isMainInterface: {{ .values.isMainInterface | default "no" | quote }}
tier: {{ .values.tier | default "internal" }}
{{- end }}

{{/*
Container image of a component: (dict "ctx" $ "values" .Values.api).
*/}}
{{- define "witness.image" -}}
{{- printf "%s:%s" .values.image.repository (.values.image.tag | default .ctx.Chart.AppVersion) }}
{{- end }}

{{/*
Pod scheduling and pull secrets shared by every component: (dict "ctx" $ "values" .Values.api).
*/}}
{{- define "witness.podScheduling" -}}
{{- with .values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (merge (dict) .values.nodeSelector .ctx.Values.chartNodeSelector) }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Name of the ConfigMap holding the writer policy.
*/}}
{{- define "witness.policyConfigMap" -}}
{{- if .Values.policy.json }}
{{- printf "%s-policy" (include "witness.fullname" .) }}
{{- else }}
{{- required "policy.existingConfigMap (or policy.json) is required" .Values.policy.existingConfigMap }}
{{- end }}
{{- end }}

{{/*
Volume with the writer policy, mounted at /etc/witness.
*/}}
{{- define "witness.policyVolume" -}}
- name: policy
  configMap:
    name: {{ include "witness.policyConfigMap" . }}
    items:
      - key: {{ .Values.policy.key }}
        path: policy.json
{{- end }}

{{/*
The database DSN as an environment variable: (dict "ctx" $ "name" "WITNESS_DB").
*/}}
{{- define "witness.databaseEnv" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ required "database.existingSecret is required" .ctx.Values.database.existingSecret }}
      key: {{ .ctx.Values.database.key }}
{{- end }}
