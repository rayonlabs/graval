{{- define "graval.labels" -}}
app.kubernetes.io/name: graval
redis-access: "true"
db-access: "true"
{{- end }}

{{- define "gravaldb.labels" -}}
app.kubernetes.io/name: gravaldb
{{- end }}
