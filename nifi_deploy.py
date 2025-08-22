#!/usr/bin/env python3
"""
nifi_deploy.py – NiFi deployment script
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
import uuid
from getpass import getpass
from pathlib import Path
import warnings
# Suppress the deprecation warning from the cryptography module.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import cryptography
# Suppress the SSL warning message
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
from requests.auth import HTTPBasicAuth

try:
    from requests_kerberos import HTTPKerberosAuth, DISABLED, REQUIRED
    _KERBEROS_AVAILABLE = True
except ImportError:
    _KERBEROS_AVAILABLE = False
    class HTTPKerberosAuth(object):
        pass
    REQUIRED = None


# ---------- logging ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s"
)
LOG = logging.getLogger("nifi-deploy")


class DeployError(RuntimeError):
    pass


# ---------- HTTP wrapper ----------------------------------------------
def _http(method, url, hdr, json_body=None, verify_ssl=True, timeout=30):
    """
    Send HTTP request, raise DeployError on ≥400, return JSON (or {}).
    """
    fn = getattr(requests, method.lower())
    headers = dict(hdr) if hdr else {}
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    LOG.debug("%s %s", method.upper(), url)
    r = fn(url, headers=headers, json=json_body, timeout=timeout, verify=verify_ssl)
    if r.status_code >= 400:
        raise DeployError("%s %s -> %s %s" % (method.upper(), url, r.status_code, r.text))
    if r.text:
        try:
            return r.json()
        except ValueError:
            return {}
    return {}


# ---------- get nifi access token --------------------------------------
def _fetch_token(base_url, basic_user, basic_pass, krb_auth, verify_ssl):
    api_endpoint = "/access/token" if basic_user else "/access/kerberos"
    token_ep = base_url.rstrip("/") + api_endpoint
    data = {"username": basic_user, "password": basic_pass} if basic_user else None
    if basic_user:
        r = requests.post(
            token_ep,
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            auth=None if data else krb_auth,
            timeout=15,
            verify=verify_ssl,
        )
    else:
        r = requests.post(
            token_ep,
            auth=krb_auth,
            timeout=15,
            verify=verify_ssl,
        )

    if (r.status_code < 200) or (r.status_code >= 300):
        raise DeployError(
            "Cannot get token from %s -> %s %s" % (token_ep, r.status_code, r.text)
        )
    return r.text.strip()

# ---------- get nifi registry token -------------------------------------
def _fetch_registry_token(base_url, basic_user, basic_pass, krb_auth, verify_ssl):
    api_endpoint = "/access/token" if basic_user else "/access/token/kerberos"
    token_ep = base_url.rstrip("/") + api_endpoint
    if basic_user:
        r = requests.post(
            token_ep,
            auth=(basic_user, basic_pass),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=15,
            verify=verify_ssl,
        )
    else:
        r = requests.post(
            token_ep,
            auth=krb_auth,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=15,
            verify=verify_ssl,
        )
    if (r.status_code < 200) or (r.status_code >= 300):
        raise DeployError("Cannot get token from %s -> %s %s" % (token_ep, r.status_code, r.text))
    return r.text.strip()


def prepare_auth_headers(args):
    # basic vs Kerberos
    basic_user = args.username
    basic_pass = args.password
    if basic_user and basic_pass is None:
        basic_pass = getpass("NiFi password: ")

    krb_auth = None
    if args.principal:
        if not _KERBEROS_AVAILABLE:
            raise DeployError("requests-kerberos not installed.")
        if args.keytab:
            res = subprocess.run(
                ["kinit", "-kt", args.keytab, args.principal],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                #text=True,
            )
            if res.returncode != 0:
                raise DeployError("kinit failed: " + str(res.stderr.strip()))
        krb_auth = HTTPKerberosAuth(mutual_authentication=DISABLED)

    verify_ssl = not args.insecure
    nifi_hdr = {}
    reg_hdr = {}

    if args.nifi_url:
        tok = _fetch_token(args.nifi_url, basic_user, basic_pass, krb_auth, verify_ssl)
        nifi_hdr = {"Authorization": "Bearer " + tok}
    if args.registry_url:
        tok = _fetch_registry_token(
            args.registry_url, basic_user, basic_pass, krb_auth, verify_ssl
        )
        reg_hdr = {"Authorization": "Bearer " + tok}
    return nifi_hdr, reg_hdr


# ---------- Registry helpers -----------------------------------------------
def reg_bucket_id(reg, bucket, hdr, ssl):
    for b in _http("get", reg + "/buckets", hdr, verify_ssl=ssl):
        if bucket in (b["identifier"], b["name"]):
            return b["identifier"]
    return None


def reg_create_bucket(reg, bucket, desc, hdr, ssl):
    data = _http(
        "post",
        reg + "/buckets",
        hdr,
        {"name": bucket, "description": desc or ""},
        verify_ssl=ssl,
    )
    LOG.info("Bucket '%s' created (id=%s)", bucket, data["identifier"])
    return data["identifier"]


def reg_flow_id(reg, bucket_id, flow, hdr, ssl):
    flows = _http(
        "get", f"{reg}/buckets/{bucket_id}/flows", hdr, verify_ssl=ssl
    )
    for f in flows:
        if flow in (f["identifier"], f["name"]):
            return f["identifier"]
    return None


def reg_create_flow(reg, bucket_id, flow, desc, hdr, ssl):
    data = _http(
        "post",
        f"{reg}/buckets/{bucket_id}/flows",
        hdr,
        {"name": flow, "description": desc or ""},
        verify_ssl=ssl,
    )
    LOG.info("Flow '%s' created (id=%s)", flow, data["identifier"])
    return data["identifier"]


def reg_import_version(reg, bucket_id, flow_id, snapshot, hdr, ssl):
    data = _http(
        "post",
        f"{reg}/buckets/{bucket_id}/flows/{flow_id}/versions/import",
        hdr,
        snapshot,
        verify_ssl=ssl,
    )
    ver = data["snapshotMetadata"]["version"]
    LOG.info("Imported version %s into flow %s", ver, flow_id)
    return ver


def reg_latest_version(reg, bucket_id, flow_id, hdr, ssl):
    data = _http(
        "get",
        f"{reg}/buckets/{bucket_id}/flows/{flow_id}/versions/latest",
        hdr,
        verify_ssl=ssl,
    )
    return data["snapshotMetadata"]["version"]


def reg_delete_bucket_by_name(reg, bucket_name, hdr, ssl):
    """
    Delete the NiFi Registry bucket whose name == bucket_name.
    Uses revision.version from /buckets.
    """
    buckets = _http("get", reg + "/buckets", hdr, verify_ssl=ssl)
    target = None
    for b in buckets:
        if b.get("name") == bucket_name:
            target = b
            break
    if not target:
        LOG.warning("No registry bucket named '%s' found; skipping delete", bucket_name)
        return
    bucket_id = target["identifier"]
    version = (target.get("revision") or {}).get("version", 0)
    LOG.info("Deleting registry bucket '%s' (id=%s, rev=%s)", bucket_name, bucket_id, version)
    _http("delete", f"{reg}/buckets/{bucket_id}?version={version}", hdr, verify_ssl=ssl)
    LOG.info("Registry bucket '%s' deleted", bucket_name)


# ---------- NiFi helpers ----------------------------------------------------
# Update parameter context
def nifi_update_pc(nifi, pc_id, params, hdr, ssl=True, poll_secs=2, timeout=300):
    # 1.  Fetch current PC to get the freshest revision
    pc_ent = _http("get", f"{nifi}/parameter-contexts/{pc_id}", hdr, verify_ssl=ssl)
    rev    = pc_ent["revision"]

    body = {
        "revision": {
            "clientId": rev.get("clientId") or str(uuid.uuid4()),
            "version":  rev["version"]
        },
        "component": {
            "id": pc_id,
            "parameters": params
        }
    }

    # 2.  Start async update request
    req = _http(
        "post",
        f"{nifi}/parameter-contexts/{pc_id}/update-requests",
        hdr,
        body,
        verify_ssl=ssl,
    )
    req_id = req["request"]["requestId"]
    LOG.info("Started Parameter-Context (%s) update request %s", pc_id, req_id)

    # 3.  Poll global update-request endpoint until complete
    deadline = time.time() + timeout
    while True:
        time.sleep(poll_secs)
        try:
            stat = _http(
                "get",
                f"{nifi}/parameter-contexts/update-requests/{req_id}",
                hdr,
                verify_ssl=ssl,
            )["request"]
        except DeployError as e:
            if "404" in str(e):
                break
            raise

        if stat["complete"]:
            if stat.get("failureReason"):
                _cleanup_request(nifi, req_id, hdr, ssl)
                raise DeployError("PC update failed: " + stat["failureReason"])
            break

        if time.time() > deadline:
            raise DeployError("Timeout waiting for Parameter-Context update")

    # 4.  Delete request object
    _cleanup_request(nifi, req_id, hdr, ssl)
    LOG.info("Parameter-Context %s updated (%s parameters)", pc_id, len(params))

def _cleanup_request(nifi, req_id, hdr, ssl):
    try:
        _http(
            "delete",
            f"{nifi}/parameter-contexts/update-requests/{req_id}",
            hdr,
            verify_ssl=ssl,
        )
    except DeployError as e:
        if "404" not in str(e):
            raise

def nifi_root_pg(nifi, hdr, ssl):
    d = _http("get", nifi + "/flow/process-groups/root", hdr, verify_ssl=ssl)
    return d["processGroupFlow"]["id"]

def strip_last_path_segment(url):
    url = url.rstrip('/')
    rindex = url.rfind('/')
    if rindex == -1:
        return url
    return url[:rindex]

def nifi_reg_client_id(nifi, reg_url, hdr, ssl):
    clients = _http("get", nifi + "/controller/registry-clients", hdr, verify_ssl=ssl)[
        "registries"
    ]
    for c in clients:
        #if c["component"]["uri"].rstrip("/") == reg_url.rstrip("/"):
        if strip_last_path_segment(c["component"]["uri"].rstrip("/")) == strip_last_path_segment(reg_url.rstrip("/")):
            return c["id"]
    raise DeployError("No registry-client in NiFi matches %s" % reg_url)


def nifi_search_pg(nifi, name, hdr, ssl):
    res = _http("get", nifi + "/flow/search-results?q=" + name, hdr, verify_ssl=ssl)
    for hit in res["searchResultsDTO"]["processGroupResults"]:
        if hit["name"] == name:
            return hit["id"]
    return None

def nifi_schedule_pg(nifi, pg_id, state, hdr, ssl, retries=0, wait_secs=3):
    _http(
        "put",
        nifi + "/flow/process-groups/" + pg_id,
        hdr,
        {"id": pg_id, "state": state},
        verify_ssl=ssl,
    )
    LOG.info("Process-group %s set to %s", pg_id, state)

    if state != "RUNNING" or retries <= 0:
        return

    for attempt in range(1, retries + 1):
        time.sleep(wait_secs)
        st = _http(
            "get",
            f"{nifi}/flow/process-groups/{pg_id}/status",
            hdr,
            verify_ssl=ssl,
        )
        agg = (st.get("processGroupStatus") or {}).get("aggregateSnapshot") or {}
        stopped  = int(agg.get("stoppedCount", 0) or 0)
        invalid  = int(agg.get("invalidCount", 0) or 0)
        disabled = int(agg.get("disabledCount", 0) or 0)

        if stopped == 0 and invalid == 0 and disabled == 0:
            LOG.info("PG %s is fully RUNNING (no stopped/invalid/disabled components).", pg_id)
            return

        LOG.info(
            "PG %s start check (attempt %d/%d): stopped=%d invalid=%d disabled=%d -> retry RUNNING",
            pg_id, attempt, retries, stopped, invalid, disabled,
        )
        _http(
            "put",
            nifi + "/flow/process-groups/" + pg_id,
            hdr,
            {"id": pg_id, "state": "RUNNING"},
            verify_ssl=ssl,
        )

    LOG.warning(
        "PG %s: some components remained stopped/invalid/disabled after %d retries. Inspect NiFi UI.",
        pg_id, retries,
    )


def nifi_create_pg_from_registry(
    nifi,
    parent_pg,
    name,
    reg_id,
    bucket_id,
    flow_id,
    version,
    hdr,
    ssl,
):
    body = {
        "revision": {"version": 0},
        "component": {
            "name": name,
            "position": {"x": 0.0, "y": 0.0},
            "versionControlInformation": {
                "registryId": reg_id,
                "bucketId": bucket_id,
                "flowId": flow_id,
                "version": version,
            },
        },
    }
    data = _http(
        "post",
        f"{nifi}/process-groups/{parent_pg}/process-groups",
        hdr,
        body,
        verify_ssl=ssl,
    )
    LOG.info("Created PG '%s' (id=%s)", name, data["id"])
    return data["id"]


def nifi_pc_id(nifi, name, hdr, ssl):
    pcs = _http("get", nifi + "/flow/parameter-contexts", hdr, verify_ssl=ssl)[
        "parameterContexts"
    ]
    for pc in pcs:
        if name in (pc["component"]["name"], pc["component"]["id"]):
            return pc["component"]["id"]
    return None


def nifi_create_pc(nifi, name, params, hdr, ssl, desc=""):
    body = {
        "revision": {"version": 0},
        "component": {"name": name, "description": desc, "parameters": params},
    }
    pc = _http("post", nifi + "/parameter-contexts", hdr, body, verify_ssl=ssl)
    LOG.info("Created Parameter-Context '%s' (id=%s)", name, pc["id"])
    return pc["id"]


def nifi_bind_pc(nifi, pg_id, pc_id, hdr, ssl):
    for attempt in range(3):
        pg = _http("get", nifi + "/process-groups/" + pg_id, hdr, verify_ssl=ssl)
        rev = pg["revision"]
        pg["component"]["parameterContext"] = {"id": pc_id}

        pg["revision"]["clientId"] = rev.get("clientId") or str(uuid.uuid4())
        #pg["revision"]["version"] += 1
        try:
            _http("put", nifi + "/process-groups/" + pg_id, hdr, pg, verify_ssl=ssl)
            LOG.info("Bound PG %s -> PC %s", pg_id, pc_id)
            return
        except DeployError as e:
            if "is not the " in str(e) and attempt < 2:
                LOG.info("409 revision conflict for %s; retrying", pg_id)
                continue
            raise

def nifi_upgrade_pg(
    nifi_url,
    pg_id,
    target_version,
    hdr,
    verify_ssl=True,
    poll_secs=2,
    timeout_secs=300,
):
    """
    Change the version of a version-controlled PG to 'target_version'.

    Raises DeployError on failure / timeout.
    """
    # ------------------------------------------------------------------
    # 1.  Fetch current PG entity   (to get fresh revision + VCI)
    # ------------------------------------------------------------------
    pg_entity = _http(
        "get", f"{nifi_url}/process-groups/{pg_id}", hdr, verify_ssl=verify_ssl
    )
    revision = pg_entity["revision"]           # {'clientId': .., 'version': n}
    vci      = pg_entity["component"]["versionControlInformation"]

    if vci is None:
        raise DeployError("Process-group is not under version control")

    if target_version == vci["version"]:
        LOG.info("PG already at requested version %s", target_version)
        return

    # ------------------------------------------------------------------
    # 2.  Build full VersionControlInformationEntity payload
    # ------------------------------------------------------------------
    body = {
        "processGroupRevision": {
            "clientId": revision.get("clientId") or str(uuid.uuid4()),
            "version": revision["version"],
        },
        "disconnectedNodeAcknowledged": False,
        "versionControlInformation": {
            "groupId":     vci["groupId"],
            "registryId":  vci["registryId"],
            "bucketId":    vci["bucketId"],
            "flowId":      vci["flowId"],
            "version":     target_version,
            # optional fields that help audit/UI (but not strictly required)
            "registryName": vci.get("registryName"),
            "bucketName":   vci.get("bucketName"),
            "flowName":     vci.get("flowName"),
            "flowDescription": vci.get("flowDescription"),
        },
    }

    # ------------------------------------------------------------------
    # 3.  POST async update-request
    # ------------------------------------------------------------------
    req = _http(
        "post",
        f"{nifi_url}/versions/update-requests/process-groups/{pg_id}",
        hdr,
        body,
        verify_ssl=verify_ssl,
    )
    req_id = req["request"]["requestId"]
    LOG.info("Initiated flow-upgrade request %s → version %s", req_id, target_version)

    # ------------------------------------------------------------------
    # 4.  Poll until complete
    # ------------------------------------------------------------------
    deadline = time.time() + timeout_secs
    while True:
        time.sleep(poll_secs)
        stat = _http(
            "get",
            f"{nifi_url}/versions/update-requests/{req_id}",
            hdr,
            verify_ssl=verify_ssl,
        )["request"]

        if stat["complete"]:
            if stat.get("failureReason"):
                # Always DELETE the request first, then raise error
                _http(
                    "delete",
                    f"{nifi_url}/versions/update-requests/{req_id}",
                    hdr,
                    verify_ssl=verify_ssl,
                )
                raise DeployError("Upgrade failed: " + stat["failureReason"])
            break

        if time.time() > deadline:
            raise DeployError("Timed-out waiting for PG upgrade to finish")

    # ------------------------------------------------------------------
    # 5.  Clean-up
    # ------------------------------------------------------------------
    _http(
        "delete",
        f"{nifi_url}/versions/update-requests/{req_id}",
        hdr,
        verify_ssl=verify_ssl,
    )
    LOG.info("Process-group %s successfully upgraded to version %s", pg_id, target_version)


# --- Enable controller services associated with a PG
def enable_controller_services(nifi, pg_id, hdr, verify_ssl=True, poll_secs=2, timeout_secs=60):
    LOG.info("Enabling controller-services in PG %s …", pg_id)

    # 1. list controller services
    cs_list = _http(
        "get",
        f"{nifi}/flow/process-groups/{pg_id}/controller-services",
        hdr,
        verify_ssl=verify_ssl,
    )["controllerServices"]

    # 2. enable any disabled controller services
    for cs in cs_list:
        comp = cs["component"]
        if comp["state"] == "DISABLED":
            rev = cs["revision"]
            body = {
                "revision": {"clientId": rev.get("clientId") or str(uuid.uuid4()),
                             "version":  rev["version"]},
                "component": {"id": comp["id"], "state": "ENABLED"},
            }
            _http(
                "put",
                f"{nifi}/controller-services/{comp['id']}",
                hdr,
                body,
                verify_ssl=verify_ssl,
            )
            LOG.debug("Sent ENABLE to CS %s", comp["name"])

    # 3. poll until every CS is ENABLED + VALID
    deadline = time.time() + timeout_secs
    while True:
        all_ok = True
        for cs in _http(
            "get",
            f"{nifi}/flow/process-groups/{pg_id}/controller-services",
            hdr,
            verify_ssl=verify_ssl,
        )["controllerServices"]:
            state = cs["component"]["state"]
            valid = cs["component"]["validationStatus"] == "VALID"

            if state != "ENABLED" or not valid:
                all_ok = False
                LOG.debug("CS %s still %s / %s",
                          cs["component"]["name"], state,
                          cs["component"]["validationStatus"])
        if all_ok:
            LOG.info("All controller-services ENABLED & VALID.")
            break

        if time.time() > deadline:
            raise DeployError("Timeout: controller services not all enabled/valid")
        time.sleep(poll_secs)


# --- Disable controller services for a PG (includes descendants)
def disable_controller_services(nifi, pg_id, hdr, verify_ssl=True, poll_secs=2, timeout_secs=120):
    LOG.info("Disabling controller-services in PG %s …", pg_id)

    # 0. Attempt group-scope deactivation (best-effort; NiFi will handle ordering)
    try:
        _http(
            "put",
            f"{nifi}/flow/process-groups/{pg_id}/controller-services",
            hdr,
            {"id": pg_id, "state": "DISABLED"},
            verify_ssl=verify_ssl,
        )
    except DeployError as e:
        LOG.debug("Group-scope deactivate returned: %s", e)

    # 1. Iterate + send DISABLED to any remaining ENABLED services (descendants included)
    deadline = time.time() + timeout_secs
    while True:
        listing = _http(
            "get",
            f"{nifi}/flow/process-groups/{pg_id}/controller-services"
            f"?includeAncestorGroups=false&includeDescendantGroups=true",
            hdr,
            verify_ssl=verify_ssl,
        )
        items = listing.get("controllerServices", [])
        if not items:
            LOG.info("No controller-services under target group.")
            return

        not_disabled = []
        for cs in items:
            comp = cs["component"]
            state = comp.get("state")
            if state != "DISABLED":
                not_disabled.append(comp["id"])
                # best-effort individual disable
                rev = cs["revision"]
                body = {
                    "revision": {"clientId": rev.get("clientId") or str(uuid.uuid4()),
                                 "version":  rev["version"]},
                    "component": {"id": comp["id"], "state": "DISABLED"},
                }
                try:
                    _http("put", f"{nifi}/controller-services/{comp['id']}", hdr, body, verify_ssl=verify_ssl)
                except DeployError as e:
                    LOG.debug("Disable CS %s failed (will retry/poll): %s", comp.get("name"), e)

        # 2. Poll until all show DISABLED
        done = True
        after = _http(
            "get",
            f"{nifi}/flow/process-groups/{pg_id}/controller-services"
            f"?includeAncestorGroups=false&includeDescendantGroups=true",
            hdr,
            verify_ssl=verify_ssl,
        ).get("controllerServices", [])
        for cs in after:
            if cs["component"].get("state") != "DISABLED":
                done = False
                break

        if done:
            LOG.info("All controller-services DISABLED.")
            return

        if time.time() > deadline:
            raise DeployError("Timeout: controller services not all disabled")
        time.sleep(poll_secs)


def nifi_upgrade_pg_deleteme(nifi, pg_id, reg_id, bucket_id, flow_id, version, hdr, ssl):
    body = {
        "versionControlInformation": {
            "groupId": pg_id,
            "registryId": reg_id,
            "bucketId": bucket_id,
            "flowId": flow_id,
            "version": version,
        }
    }
    req = _http(
        "post",
        f"{nifi}/versions/update-requests/process-groups/{pg_id}",
        hdr,
        body,
        verify_ssl=ssl,
    )
    rid = req["request"]["requestId"]
    while True:
        time.sleep(1)
        stat = _http(
            "get", f"{nifi}/versions/update-requests/{rid}", hdr, verify_ssl=ssl
        )
        if stat["request"]["complete"]:
            if stat["request"]["failureReason"]:
                raise DeployError(stat["request"]["failureReason"])
            _http("delete", f"{nifi}/versions/update-requests/{rid}", hdr, verify_ssl=ssl)
            break
    LOG.info("PG %s upgraded to version %s", pg_id, version)


# --- Queue drain / PG delete helpers ---------------------------------------
def nifi_drop_all_queues(nifi, pg_id, hdr, verify_ssl=True, poll_secs=2, timeout_secs=300):
    LOG.info("Dropping all queues in PG %s …", pg_id)
    req = _http(
        "post",
        f"{nifi}/process-groups/{pg_id}/empty-all-connections-requests",
        hdr,
        verify_ssl=verify_ssl,
    )
    drop = req.get("dropRequest") or req
    drop_id = drop.get("id") or (drop.get("dropRequest") or {}).get("id")
    if not drop_id:
        raise DeployError("Could not obtain queue drop-request id")

    deadline = time.time() + timeout_secs
    try:
        while True:
            stat = _http(
                "get",
                f"{nifi}/process-groups/{pg_id}/empty-all-connections-requests/{drop_id}",
                hdr,
                verify_ssl=verify_ssl,
            )
            dr = stat.get("dropRequest") or stat
            pct = dr.get("percentCompleted")
            finished = dr.get("finished")
            LOG.debug("Queue drop status: %s%%", pct)
            if finished:
                if dr.get("failureReason"):
                    raise DeployError("Queue drop failed: " + dr["failureReason"])
                LOG.info("All queues dropped.")
                break

            if time.time() > deadline:
                raise DeployError("Timeout while dropping connection queues")
            time.sleep(poll_secs)
    finally:
        # best-effort cleanup of request
        try:
            _http(
                "delete",
                f"{nifi}/process-groups/{pg_id}/empty-all-connections-requests/{drop_id}",
                hdr,
                verify_ssl=verify_ssl,
            )
        except DeployError:
            pass


def nifi_delete_pg(nifi, pg_id, hdr, verify_ssl=True):
    ent = _http("get", f"{nifi}/process-groups/{pg_id}", hdr, verify_ssl=verify_ssl)
    rev = ent["revision"]
    name = (ent.get("component") or {}).get("name", "")
    version = rev["version"]
    client_id = str(uuid.uuid4())
    LOG.info("Deleting PG '%s' (%s) …", name, pg_id)
    _http(
        "delete",
        f"{nifi}/process-groups/{pg_id}?version={version}&clientId={client_id}",
        hdr,
        verify_ssl=verify_ssl,
    )
    LOG.info("PG '%s' deleted", name)
    return name


# ---------- CLI parsing -----------------------------------------------------
def parser():
    p = argparse.ArgumentParser(description="NiFi / NiFi-Registry deploy CLI")
    p.add_argument("--nifi-url", required=True)
    p.add_argument("--registry-url", required=True)
    p.add_argument("--site-role", choices=["active", "passive"], default="active",
               help="Site role: active starts flow & services; passive leaves them stopped")


    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--principal")
    grp.add_argument("--username")
    p.add_argument("--password")
    p.add_argument("--keytab")

    p.add_argument("-k", "--insecure", action="store_true")
    p.add_argument("-v", "--debug", action="store_true")

    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("create-bucket")
    s.add_argument("--bucket", required=True)
    s.add_argument("--description")

    s = sub.add_parser("upload-flow")
    s.add_argument("--bucket", required=True)
    s.add_argument("--flow", required=True)
    s.add_argument("--file", required=True, type=Path)
    s.add_argument("--description")

    s = sub.add_parser("instantiate-flow")
    s.add_argument("--bucket", required=True)
    s.add_argument("--flow", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--env", required=True)
    s.add_argument("--version", type=int)
    s.add_argument("--parent-id")
    s.add_argument("--param-file", type=Path)

    s = sub.add_parser("upgrade-flow")
    s.add_argument("--name", required=True)
    s.add_argument("--version", type=int)
    s.add_argument("--param-file", type=Path)

    # subcommand update-pc
    s = sub.add_parser("update-pc", help="Update an existing Parameter Context")
    s.add_argument("--name", required=True, help="Parameter Context name or ID")
    s.add_argument("--param-file", type=Path, required=True, help="JSON with parameters")

    for cmd in ("start-flow", "stop-flow"):
        s = sub.add_parser(cmd)
        s.add_argument("--name", required=True)

    # --- NEW: cleanup ----------------------------------------------------
    s = sub.add_parser("cleanup", help="Disable CS, stop PG, drop queues, delete PG and matching Registry bucket")
    s.add_argument("--name", required=True, help="Process Group name to clean up")

    return p


# ---------- MAIN ------------------------------------------------------------
def main():
    args = parser().parse_args()
    if args.debug:
        LOG.setLevel(logging.DEBUG)

    nifi_hdr, reg_hdr = prepare_auth_headers(args)
    ssl = not args.insecure
    reg = args.registry_url.rstrip("/")
    nifi = args.nifi_url.rstrip("/")

    # -- create-bucket -------------------------------------------------------
    if args.cmd == "create-bucket":
        if reg_bucket_id(reg, args.bucket, reg_hdr, ssl):
            LOG.warning("Bucket '%s' already exists", args.bucket)
        else:
            reg_create_bucket(reg, args.bucket, args.description, reg_hdr, ssl)
        return

    # -- upload-flow ---------------------------------------------------------
    if args.cmd == "upload-flow":
        bucket_id = reg_bucket_id(reg, args.bucket, reg_hdr, ssl)
        if not bucket_id:
            raise DeployError("Bucket not found")
        flow_id = reg_flow_id(reg, bucket_id, args.flow, reg_hdr, ssl)
        if not flow_id:
            flow_id = reg_create_flow(reg, bucket_id, args.flow, args.description, reg_hdr, ssl)
        snapshot = json.loads(args.file.read_text())
        # override the name with the args.flow
        snapshot["flowContents"]["name"]=args.flow
        rc = reg_import_version(reg, bucket_id, flow_id, snapshot, reg_hdr, ssl)
        return rc

    # -- instantiate-flow ----------------------------------------------------
    if args.cmd == "instantiate-flow":
        bucket_id = reg_bucket_id(reg, args.bucket, reg_hdr, ssl)
        flow_id = reg_flow_id(reg, bucket_id, args.flow, reg_hdr, ssl)
        version = args.version or reg_latest_version(reg, bucket_id, flow_id, reg_hdr, ssl)
        parent = args.parent_id or nifi_root_pg(nifi, nifi_hdr, ssl)
        reg_client = nifi_reg_client_id(nifi, reg, nifi_hdr, ssl)
        pg_id = nifi_create_pg_from_registry(
            nifi, parent, args.name, reg_client, bucket_id, flow_id, version, nifi_hdr, ssl
        )

        # Param‐context
        pc_name = "{}_{}".format(args.env, args.name)
        pc_id = nifi_pc_id(nifi, pc_name, nifi_hdr, ssl)
        params = []
        if args.param_file:
            with args.param_file.open() as f:
                pc_cfg = json.load(f)
            params = [
                {
                    "parameter": {
                        "name": p["name"],
                        "value": p.get("value"),
                        "sensitive": p.get("sensitive", False),
                    }
                }
                for p in pc_cfg.get("parameters", [])
            ]
        if pc_id:
            if params:
                nifi_update_pc(nifi, pc_id, params, nifi_hdr, ssl)
        else:                                      # create new
            pc_id = nifi_create_pc(
                nifi, pc_name, params, nifi_hdr, ssl, desc="Auto PC for " + pc_name
            )

        # Bind PC to PG
        nifi_bind_pc(nifi, pg_id, pc_id, nifi_hdr, ssl)

	if args.site_role == "active":
	    # Enable controller services
	    enable_controller_services(nifi, pg_id, nifi_hdr, ssl, 2, 30)
	    # Start the process group
	    nifi_schedule_pg(nifi, pg_id, "RUNNING", nifi_hdr, ssl ,retries=6, wait_secs=5)
	else:
	    LOG.info("Passive site: skipping controller-services enable and flow start.")
	return


    # -- upgrade-flow --------------------------------------------------------
    if args.cmd == "upgrade-flow":
        pg_id = nifi_search_pg(nifi, args.name, nifi_hdr, ssl)
        if not pg_id:
            raise DeployError("PG not found")
        stat = _http( "get", nifi + "/versions/process-groups/" + pg_id, nifi_hdr, verify_ssl=ssl)

        vci = stat["versionControlInformation"]
        target = args.version or reg_latest_version(
            reg, vci["bucketId"], vci["flowId"], reg_hdr, ssl
        )
        if target == vci["version"]:
            LOG.info("Already at version %s", target)
            return

        # Stop the PG
        nifi_schedule_pg(nifi, pg_id, "STOPPED", nifi_hdr, ssl,retries=6, wait_secs=5)

        # Update parameter context
        if args.param_file:
            # Identify parameter context bound to this PG
            bound_pc = _http(
                "get", nifi + "/process-groups/" + pg_id, nifi_hdr, verify_ssl=ssl
            )["component"]["parameterContext"]
            if not bound_pc:
                raise DeployError("PG has no Parameter-Context to update")
            with args.param_file.open() as f:
                new_params = [
                    {
                        "parameter": {
                            "name": p["name"],
                            "value": p.get("value"),
                            "sensitive": p.get("sensitive", False),
                        }
                    }
                    for p in json.load(f)["parameters"]
                ]
            nifi_update_pc(nifi, bound_pc["id"], new_params, nifi_hdr, ssl)

        nifi_upgrade_pg(
            nifi,
            pg_id,
            target,
            nifi_hdr,
            ssl,
        )
	if args.site_role == "active":
	    nifi_schedule_pg(nifi, pg_id, "RUNNING", nifi_hdr, ssl,retries=6, wait_secs=5)
	else:
	    LOG.info("Passive site: leaving process group STOPPED after upgrade.")
	return


    if args.cmd == "update-pc":
        pc_id = nifi_pc_id(nifi, args.name, nifi_hdr, ssl)
        if not pc_id:
            raise DeployError("Parameter-Context not found")
        with args.param_file.open() as f:
            new_params = [
                {
                    "parameter": {
                        "name": p["name"],
                        "value": p.get("value"),
                        "sensitive": p.get("sensitive", False),
                    }
                }
                for p in json.load(f)["parameters"]
            ]
        nifi_update_pc(nifi, pc_id, new_params, nifi_hdr, ssl)
        return

    # -- start-flow / stop-flow ---------------------------------------------
    if args.cmd in ("start-flow", "stop-flow"):
        pg_id = nifi_search_pg(nifi, args.name, nifi_hdr, ssl)
        if not pg_id:
            raise DeployError("PG not found")
        new_state = "RUNNING" if args.cmd == "start-flow" else "STOPPED"
        nifi_schedule_pg(nifi, pg_id, new_state, nifi_hdr, ssl,retries=6, wait_secs=5)
        return

    # -- cleanup -------------------------------------------------------------
    if args.cmd == "cleanup":
        pg_id = nifi_search_pg(nifi, args.name, nifi_hdr, ssl)
        if not pg_id:
            raise DeployError("PG not found")

        # 1) Try to disable controller services first
        try:
            disable_controller_services(nifi, pg_id, nifi_hdr, ssl, poll_secs=2, timeout_secs=90)
        except DeployError as e:
            LOG.warning("Could not fully disable controller services before stopping PG (%s). Proceeding to stop PG, then retry.", e)

        # 2) Stop the process group
        nifi_schedule_pg(nifi, pg_id, "STOPPED", nifi_hdr, ssl,retries=6, wait_secs=5)

        # 2b) Retry CS disable in case referencing components prevented it earlier
        try:
            disable_controller_services(nifi, pg_id, nifi_hdr, ssl, poll_secs=2, timeout_secs=60)
        except DeployError as e:
            LOG.warning("Controller services still not all disabled; continuing with cleanup: %s", e)

        # 3) Empty all queues
        nifi_drop_all_queues(nifi, pg_id, nifi_hdr, ssl, poll_secs=2, timeout_secs=300)

        # 4) Delete the process group (capture name for registry bucket)
        pg_name = nifi_delete_pg(nifi, pg_id, nifi_hdr, ssl)

        # 5) Delete matching registry bucket (name == PG name)
        reg_delete_bucket_by_name(reg, pg_name, reg_hdr, ssl)
        return


if __name__ == "__main__":
    try:
        rc = main()
        rc = 0 if not rc else rc
        sys.exit(rc)
    except DeployError as e:
        LOG.error("ERROR: %s", e)
        sys.exit(2)
    except KeyboardInterrupt:
        LOG.warning("Interrupted")
        sys.exit(130)
