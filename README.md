# NiFi Deploy Process Group using NiFi registry
This project supports deploying NiFi Process Group into a live NiFi cluster using NiFi registry

# Pre-requesites
- A live NiFi cluster
- A live NiFi registry
- A user with access to REST API to create buckets, perform deployments, create parameter contexts, etc.

## Inputs
- process group name
- nifi-url
- registry-url
- username/password or
- principal/keytab
- command (create-bucket, upload-flow, instantiate-flow, upgrade-flow) and command specific arguments

## When to use this script
This script can be used to create a bucket on the Registry, upload a flow to it, instantiate a process group with a flow form registry, upgrade a flow
Check main.sh script to see how to invoke this script for various scenarios

## How to use
Check main.sh script to see how to invoke this script for various scenarios

# Configure environmental values
update set_env.sh as per your environment and source it before running nifi_deploy.py commands
