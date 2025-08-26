#!/usr/bin/env python3
"""
nifi_dr.py – NiFi script to help with status check and failover
Working:
    1. Performs failover at the application level (process group)
    2. Takes the following input params
       a. Process group (name or id)
       b. current active URL
       c. current standby URL,
       d. action (failover, status)
       e. additional params specific to action
    3. If the action is failover
       a. Stop the process group on the current active side
       b. if force flag is enabled, stop immediately
       c. Otherwise, do a graceful stop, verify the process group is stopped and there are no queued or active flow files
       d. start the flow on current standby

TODO:
    1. Verify that standby is not running before proceeding with failover
    2. Do a delayed retry for upto a few min for quiese state
    3. When promoting, lets make sure the controller services are enabled
    4. pg_id for primary and standby could be different.


"""

import argparse, json, logging, os, re, subprocess, sys, time, uuid
from getpass import getpass
from pathlib import Path
import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import cryptography
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from typing import Tuple, Dict
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
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s")
LOG = logging.getLogger("nifi-dr")


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

def prepare_auth_headers(args) -> Tuple[dict, dict]:
    # basic vs Kerberos
    user = args.username
    pw   = args.password
    if user and pw is None:
        pw = getpass("Password for %s: " % user)

    krb_auth = None
    if args.principal:
        if not _KERBEROS_AVAILABLE:
            raise DeployError("requests-kerberos not installed.")
        if args.keytab:
            res = subprocess.run(
                ["kinit", "-kt", args.keytab, args.principal],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if res.returncode != 0:
                raise DeployError("kinit failed: " + str(res.stderr.strip()))
        krb_auth = HTTPKerberosAuth(mutual_authentication=DISABLED)

    verify = not args.insecure
    hdr = hdr_sb = {}
    if args.active_url:
        tok = _fetch_token(args.active_url, user, pw, krb_auth, verify)
        hdr_act = {"Authorization": "Bearer " + tok}
    if args.standby_url:
        tok = _fetch_token(args.standby_url, user, pw, krb_auth, verify)
        hdr_sb = {"Authorization": "Bearer " + tok}
    return hdr_act, hdr_sb

# ------------------- NiFi Helpers -----------------------------------------

# --- Enable controller services associated with a PG
def enable_controller_services(nifi, pg_id, hdr, verify_ssl=True, poll_secs=2, timeout_secs=60):
    LOG.info("Enabling controller-services in PG %s …", pg_id)

    # 1. list controller services
    cs_list = _http( "get", f"{nifi}/flow/process-groups/{pg_id}/controller-services", hdr,
        verify_ssl=verify_ssl,)["controllerServices"]

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
            _http( "put", f"{nifi}/controller-services/{comp['id']}", hdr, body,
                verify_ssl=verify_ssl,)
            LOG.debug("Sent ENABLE to CS %s", comp["name"])

    # 3. poll until every CS is ENABLED + VALID
    deadline = time.time() + timeout_secs
    while True:
        all_ok = True
        for cs in _http( "get",
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

# Disable controller services associated with a PG
def disable_controller_services(nifi, pg_id, hdr, verify_ssl=True, poll_secs=2, timeout_secs=120):
    LOG.info("Disabling controller-services in PG %s …", pg_id)

    # 1. list controller services
    cs_list = _http( "get", f"{nifi}/flow/process-groups/{pg_id}/controller-services", hdr,
        verify_ssl=verify_ssl,
    )["controllerServices"]

    # 2. disable any enabled controller services
    for cs in cs_list:
        comp = cs["component"]
        if comp["state"] == "ENABLED":
            rev = cs["revision"]
            body = {
                "revision": {"clientId": rev.get("clientId") or str(uuid.uuid4()),
                             "version":  rev["version"]},
                "component": {"id": comp["id"], "state": "DISABLED"},
            }
            _http( "put", f"{nifi}/controller-services/{comp['id']}", hdr, body,
                verify_ssl=verify_ssl,
            )
            LOG.debug("Sent DISABLE to CS %s", comp["name"])

    # 3. poll until every CS is DISABLED
    deadline = time.time() + timeout_secs
    while True:
        all_ok = True
        for cs in _http(
            "get", f"{nifi}/flow/process-groups/{pg_id}/controller-services", hdr,
            verify_ssl=verify_ssl,
        )["controllerServices"]:
            state = cs["component"]["state"]
            if state != "DISABLED":
                all_ok = False
                LOG.debug("CS %s still %s / %s", cs["component"]["name"], state)
        if all_ok:
            LOG.info("All controller-services DISABLED")
            break

        if time.time() > deadline:
            # Ignore the error during disabling of controller service
            return
        time.sleep(poll_secs)


def resolve_pg_id_from_name(nifi_url, pg_name, hdr, verify_ssl=True):
    search = _http("get", f"{nifi_url}/flow/search-results?q={pg_name}", hdr, verify_ssl=verify_ssl)

    matches = [hit["id"]
                for hit in search["searchResultsDTO"]["processGroupResults"]
                if hit["name"] == pg_name and hit["parentGroup"]["name"] == "NiFi Flow"]
    if len(matches) == 1:
        return matches[0]
    if len(matches) == 0:
        raise DeployError(f"No process-group named '{pg_name}' found")
    raise DeployError(f"Multiple root-level PGs named '{pg_name}' use --pg-id option")

def nifi_schedule_pg(nifi, pg_id, state, hdr, verify):
    body = {"id": pg_id, "state": state}
    _http("put", f"{nifi}/flow/process-groups/{pg_id}", hdr,
          body, verify_ssl=verify)
    LOG.info("Set PG %s → %s", pg_id, state)


def pg_snapshot(nifi_url, pg_id, hdr, verify):
    """
    Return (state, flowFilesQueued, bytesQueued, activeThreadCount) for the given process group ID.
    Falls back to summing immediate children if the PG has no aggregateSnapshot.
    """
    def snap(entity):
        return entity.get("status", {}).get("aggregateSnapshot", {}) or {}

    def get_int(s, key):
        try:
            return int(s.get(key, 0) or 0)
        except Exception:
            return 0

    # Fetch PG flow
    resp = _http( "get", f"{nifi_url}/flow/process-groups/{pg_id}", hdr, verify_ssl=verify)
    pgf = resp.get("processGroupFlow", {})

    flow = pgf.get("flow", {})
    total_ffq = total_bq = total_active = total_running = total_stopped = 0

    for group in flow.get("processGroups", []):
        s = snap(group)
        total_ffq += get_int(s, "flowFilesQueued")
        total_bq += get_int(s, "bytesQueued")
        total_active += get_int(s, "activeThreadCount")
        total_running += group.get("runningCount", 0)
        total_stopped += group.get("stoppedCount", 0)

    for proc in flow.get("processors", []):
        s = snap(proc)
        total_active += get_int(s, "activeThreadCount")
        if s.get("runStatus", "") == "Running":
            total_running += 1
        if s.get("runStatus", "") == "Stopped":
            total_stopped += 1

    for conn in flow.get("connections", []):
        s = snap(conn)
        total_ffq += get_int(s, "flowFilesQueued")
        total_bq += get_int(s, "bytesQueued")

    state = "RUNNING" if total_running > 0 or total_active > 0 else (
        "STOPPED" if total_running == 0 and total_active == 0 else "MIXED"
    )
    return state, total_ffq, total_bq, total_active


def pg_snapshot2(nifi, pg_id, hdr, verify):
    flow = _http("get", f"{nifi}/flow/process-groups/{pg_id}",
                 hdr, verify_ssl=verify)
    with open("/tmp/pramodh.json", "w") as f:
        json.dump(flow, f, indent=4)
    snap = flow["processGroupFlow"]["status"]["aggregateSnapshot"]
    state = snap["runStatus"]
    active = snap["activeThreadCount"]
    queued = int(snap["flowFilesQueued"].split()[0].split("/")[0])
    return state, queued, active


def verify_pg_quiesced(nifi, pg_id, hdr, verify):
    s,ffq,bq,a = pg_snapshot(nifi, pg_id, hdr, verify)
    if s != "STOPPED" or a != 0 or ffq != 0:
        raise DeployError("PG %s not quiesced – state=%s queued=%d active=%d"
                          % (pg_id, s, ffq, a))

def get_sources(nifi_url, pg_id, headers, verify_ssl=True):
    LOG.debug("Fetching flow structure for PG %s", pg_id)
    flow = _http("get", f"{nifi_url}/flow/process-groups/{pg_id}",
                 headers, verify_ssl=verify_ssl)
    content = flow["processGroupFlow"]["flow"]
    processors  = content.get("processors", [])
    connections = content.get("connections", [])
    child_pgs = content.get("processGroups", [])

    dest_ids = {conn.get("destination", {}).get("id")
                for conn in connections
                if conn.get("destination", {}).get("type") in ["PROCESSOR"]}

    source_ids = [proc["component"]["id"] for proc in processors
                  if proc["component"]["id"] not in dest_ids]
    LOG.info("Identified %d source processors in PG %s", len(source_ids), pg_id)
    return source_ids

def graceful_stop(nifi_url, pg_id, hdr, verify_ssl=True,
                  wait_seconds=30, poll_interval=2):
    LOG.info("Gracefully stopping PG %s on %s", pg_id, nifi_url)
    for pid in get_sources(nifi_url, pg_id, hdr, verify_ssl):
        proc = _http("get", f"{nifi_url}/processors/{pid}", hdr, verify_ssl, timeout=120)
        rev = proc["revision"]
        body = {"revision": {"clientId": rev.get("clientId") or str(uuid.uuid4()),
                             "version":  rev["version"]},
                "state": "STOPPED"}
        _http("put", f"{nifi_url}/processors/{pid}/run-status",
              hdr, body, verify_ssl)
        LOG.debug("Stopped source %s", pid)

    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        state, ffq, bq, thr = pg_snapshot(nifi_url, pg_id, hdr, verify_ssl)
        if ffq == 0 and thr == 0:
            break
        LOG.debug("Drain in progress: queued=%d active=%d", ffq, thr)
        time.sleep(poll_interval)
    else:
        raise DeployError("Timeout waiting for PG %s to drain" % pg_id)

    nifi_schedule_pg(nifi_url, pg_id, "STOPPED", hdr, verify_ssl)
    LOG.info("PG %s stopped & drained", pg_id)


# Fail-over
def do_failover(active_url, standby_url, active_pg_id, standby_pg_id,
                hdr_act, hdr_sb, verify_ssl, force=False, drain_timeout=30):

    # verify app is not running on standby
    verify_pg_quiesced(standby_url, standby_pg_id, hdr_sb, verify_ssl)
    LOG.info("INFO: standby to not running :%s", standby_url)

    # stop app on the active side
    if force:
        LOG.warning("FORCE mode: immediate STOP on active!")
        nifi_schedule_pg(active_url, active_pg_id, "STOPPED", hdr_act, verify_ssl)
        disable_controller_services(active_url, active_pg_id, hdr_act, verify_ssl, 2, 30)
    else:
        graceful_stop(active_url, active_pg_id, hdr_act,
                      verify_ssl=verify_ssl, wait_seconds=drain_timeout)
        disable_controller_services(active_url, active_pg_id, hdr_act, verify_ssl, 2, 30)
        verify_pg_quiesced(active_url, active_pg_id, hdr_act, verify_ssl)
        LOG.info("SUCCESS: Stopped app:%s on active site :%s", active_pg_id, active_url)

    # start app on the standby side
    enable_controller_services(standby_url, standby_pg_id, hdr_sb, verify_ssl, 2, 30)
    nifi_schedule_pg(standby_url, standby_pg_id, "RUNNING", hdr_sb, verify_ssl)
    state, _, _,_ = pg_snapshot(standby_url, standby_pg_id, hdr_sb, verify_ssl)
    if state != "RUNNING":
        raise DeployError("Stand-by PG failed to start (state=%s)" % state)
    LOG.info("SUCCESS: Promoted standby to active :%s", standby_url)

    # --- Flip parameter context site_role on both sites now that promotion succeeded
    try:
        flip_res = set_site_roles_both_sites(active_url, standby_url, active_pg_id, standby_pg_id,
                                             hdr_act, hdr_sb, verify_ssl=verify_ssl)
        LOG.info("Updated site_role on parameter contexts: %s", json.dumps(flip_res))
    except Exception as e:
        LOG.warning("Failover succeeded but updating 'site_role' failed: %s", e)

def parser():
    p = argparse.ArgumentParser(description="NiFi DR fail-over CLI")
    p.add_argument("-v", "--debug", action="count", default=0)
    pgsel = p.add_mutually_exclusive_group(required=True)
    #pgsel.add_argument("--pg-id",        required=False, help="Process-group ID to switch")
    pgsel.add_argument("--pg-name",      required=False, help="Process-group name to switch (root level)")
    p.add_argument("--username")
    p.add_argument("--active-url",   required=True)
    p.add_argument("--standby-url",  required=True)
    p.add_argument("--password")
    p.add_argument("--principal")
    p.add_argument("--keytab")
    p.add_argument("-k", "--insecure", action="store_true")


    sub = p.add_subparsers(dest="cmd")
    f = sub.add_parser("failover")
    f.add_argument("--force", action="store_true",
                   help="Immediate stop (data loss possible)")
    f.add_argument("--timeout", type=int, default=30)

    s = sub.add_parser("status")


    r = sub.add_parser("set-site-roles", help="Set parameter 'site_role' to active/passive on the two sites for the selected Process Group")
    return p

# --------------------------------------------------------------------------

# ------------------- Parameter Context: site_role helpers ------------------

def _load_pg(nifi, pg_id, hdr, verify_ssl=True):
    """Return Process Group entity (component + revision)."""
    return _http("get", f"{nifi}/process-groups/{pg_id}", hdr, verify_ssl=verify_ssl)

def _load_parameter_context(nifi, pc_id, hdr, verify_ssl=True):
    """Return Parameter Context entity."""
    return _http("get", f"{nifi}/parameter-contexts/{pc_id}", hdr, verify_ssl=verify_ssl)

def _put_parameter_context(nifi, pc_entity, hdr, verify_ssl=True):
    """PUT the Parameter Context entity back (NiFi requires full component + revision)."""
    pc_id = pc_entity["component"]["id"]
    return _http("put", f"{nifi}/parameter-contexts/{pc_id}", hdr, json_body={
        "revision": pc_entity["revision"],
        "component": pc_entity["component"],
    }, verify_ssl=verify_ssl)

def set_site_role_for_pg(nifi, pg_id, hdr, verify_ssl=True, *, role: str, description: str = "Role of this site in active/passive DR"):
    """
    Ensure the parameter `site_role` exists on the parameter context assigned to the given Process Group
    and set it to the given role ('active' or 'passive').

    Returns a dict summary with old/new values and revision.
    """
    role_norm = str(role).strip().lower()
    if role_norm not in ("active", "passive"):
        raise DeployError("role must be 'active' or 'passive'")

    # 1) Discover the PG's parameter context
    pg = _load_pg(nifi, pg_id, hdr, verify_ssl=verify_ssl)
    pc_ref = pg.get("component", {}).get("parameterContext")
    if not pc_ref or "id" not in pc_ref:
        raise DeployError(f"Process Group {pg_id} does not have a parameter context assigned.")

    pc_id = pc_ref["id"]
    # 2) Load full parameter context
    pc_entity = _load_parameter_context(nifi, pc_id, hdr, verify_ssl=verify_ssl)

    params_list = pc_entity["component"].get("parameters") or []
    # Convert to dict by name
    by_name = {}
    for entry in params_list:
        param = entry.get("parameter", {})
        name = param.get("name")
        if name:
            by_name[name] = entry

    old_val = None
    if "site_role" in by_name:
        old_val = by_name["site_role"]["parameter"].get("value")
        by_name["site_role"]["parameter"]["value"] = role_norm
        by_name["site_role"]["parameter"]["sensitive"] = False
        if description is not None:
            by_name["site_role"]["parameter"]["description"] = description
    else:
        new_entry = {
            "parameter": {
                "name": "site_role",
                "value": role_norm,
                "sensitive": False,
            }
        }
        if description is not None:
            new_entry["parameter"]["description"] = description
        by_name["site_role"] = new_entry

    # Rebuild ordered list (preserve existing order where possible, append new if needed)
    names_seen = [e.get("parameter", {}).get("name") for e in params_list if e.get("parameter")]
    new_list = []
    seen_set = set()
    for nm in names_seen:
        if nm in by_name and nm not in seen_set:
            new_list.append(by_name[nm])
            seen_set.add(nm)
    # Append any new names (like site_role) not present before
    for nm, entry in by_name.items():
        if nm not in seen_set:
            new_list.append(entry)

    pc_entity["component"]["parameters"] = new_list
    updated = _put_parameter_context(nifi, pc_entity, hdr, verify_ssl=verify_ssl)

    return {
        "parameterContextId": pc_id,
        "parameterContextName": updated["component"].get("name"),
        "oldValue": old_val,
        "newValue": role_norm,
        "revisionVersion": updated["revision"]["version"],
    }

def set_site_roles_both_sites(active_nifi, standby_nifi, active_pg_id, standby_pg_id, hdr_act, hdr_sb, verify_ssl=True):
    """Set site_role=active on the active site and site_role=passive on the standby site for the given PG IDs.
    Returns a dict with 'active' and 'standby' results.
    """
    res_active = set_site_role_for_pg(active_nifi, active_pg_id, hdr_act, verify_ssl=verify_ssl, role="active")
    res_passive = set_site_role_for_pg(standby_nifi, standby_pg_id, hdr_sb, verify_ssl=verify_ssl, role="passive")
    return {"active": res_active, "standby": res_passive}

def main():
    args = parser().parse_args()
    if args.debug:
        LOG.setLevel(logging.DEBUG)

    hdr_act, hdr_sb = prepare_auth_headers(args)
    verify = not args.insecure
    act = args.active_url.rstrip("/")
    sb  = args.standby_url.rstrip("/")
    active_pg_id = resolve_pg_id_from_name(act, args.pg_name, hdr_act, verify)
    LOG.info("Resolved PG '%s' on active to : %s", args.pg_name, active_pg_id)

    standby_pg_id = resolve_pg_id_from_name(sb, args.pg_name, hdr_sb, verify)
    LOG.info("Resolved PG '%s' on standby to : %s", args.pg_name, standby_pg_id)

    if args.cmd == "status":
        sa = pg_snapshot(act, active_pg_id, hdr_act, verify)
        ss = pg_snapshot(sb,  standby_pg_id, hdr_sb,  verify)
        print(json.dumps({
            "active":  {"url": act, "state": sa[0], "queued": sa[1], "threads": sa[3]},
            "standby": {"url": sb,  "state": ss[0], "queued": ss[1], "threads": ss[3]},
        }, indent=2))
    
    elif args.cmd == "set-site-roles":
        # Update site_role on both clusters
        results = set_site_roles_both_sites(act, sb, active_pg_id, standby_pg_id, hdr_act, hdr_sb, verify_ssl=verify)
        print(json.dumps(results, indent=2))
    elif args.cmd == "failover":
        do_failover(act, sb, active_pg_id, standby_pg_id, hdr_act, hdr_sb,
                    verify_ssl=verify, force=args.force,
                    drain_timeout=args.timeout)
    else:
        raise DeployError("Unknown command %s" % args.cmd)

# --------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        main()
    except DeployError as e:
        LOG.error("ERROR: %s", e)
        sys.exit(2)
    except KeyboardInterrupt:
        LOG.warning("Interrupted")
        sys.exit(130)
