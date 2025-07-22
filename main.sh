#!/bin/bash

SCRIPT_DIR=.
. $SCRIPT_DIR/set_env.sh

# Set application environment
environment=${environment}
application="TestApp"
bucket_name=${application}
flow_name=${application}
pg_flow_json=TestApp.json
param_file=TestApp_param.json
target_version=

# Create bucket on registry for this application
python3 ${SCRIPT_DIR}/nifi_deploy.py --insecure \
  --nifi-url https://${NIFI_HOST}:${NIFI_PORT}/nifi-api \
  --registry-url https://${NIFI_REGISTRY_HOST}:${NIFI_REGISTRY_PORT}/nifi-registry-api \
  --principal ${KERBEROS_PRINCIPAL} --keytab ${KERBEROS_KEYTAB} \
  create-bucket --bucket ${bucket_name}
cb_rc=$?
echo "$(date)   INFO create bucket returned : $cb_rc"

# Upload flow to the registry bucket
python3 ${SCRIPT_DIR}/nifi_deploy.py --insecure \
  --nifi-url https://${NIFI_HOST}:${NIFI_PORT}/nifi-api \
  --registry-url https://${NIFI_REGISTRY_HOST}:${NIFI_REGISTRY_PORT}/nifi-registry-api \
  --principal ${KERBEROS_PRINCIPAL} --keytab ${KERBEROS_KEYTAB} \
  upload-flow --bucket ${bucket_name} --flow ${flow_name} --file ${pg_flow_json}
uf_rc=$?
echo "$(date)   INFO Upload-flow rc: $uf_rc"

if [ $uf_rc -eq 1 ]; then
    echo "$(date)   INFO Performing Initial deployment "
    # First deployment
    python3 ${SCRIPT_DIR}/nifi_deploy.py --insecure \
      --nifi-url https://${NIFI_HOST}:${NIFI_PORT}/nifi-api \
      --registry-url https://${NIFI_REGISTRY_HOST}:${NIFI_REGISTRY_PORT}/nifi-registry-api \
      --principal ${KERBEROS_PRINCIPAL} --keytab ${KERBEROS_KEYTAB} \
      instantiate-flow \
      --bucket ${bucket_name} --flow ${flow_name} \
      --name ${application} --env ${environment} --param-file ${param_file}
    if_rc=$?
    echo "$(date)   INFO Instantiate-flow rc: $if_rc"
    exit $if_rc
else
    # Upgrade the flow
    if [ ! -z "${target_version}" ]; then
        VERSION_STR=" --version ${target_version}"
    else
        VERSION_STR=""
    fi
    if [ ! -z "${param_file}" ]; then
        PARAM_STR=" --param-file ${param_file}"
    else
        PARAM_STR=""
    fi

    echo "$(date)   INFO Performing Upgrade to the flow"
    python3 ${SCRIPT_DIR}/nifi_deploy.py --insecure \
      --nifi-url https://${NIFI_HOST}:${NIFI_PORT}/nifi-api \
      --registry-url https://${NIFI_REGISTRY_HOST}:${NIFI_REGISTRY_PORT}/nifi-registry-api \
      --principal ${KERBEROS_PRINCIPAL} --keytab ${KERBEROS_KEYTAB} \
      upgrade-flow --name ${application} ${VERSION_STR} ${PARAM_STR}
    uf_rc=$?
    echo "$(date)   INFO Instantiate-flow rc: $uf_rc"
    exit $uf_rc
fi
