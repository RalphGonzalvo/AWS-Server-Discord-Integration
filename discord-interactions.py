import os
import json
import base64
import time
import boto3
from botocore.exceptions import ClientError
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import urllib.request
import urllib.error

EC2 = boto3.client("ec2")
LAMBDA = boto3.client("lambda")
SSM = boto3.client("ssm")

INSTANCE_ID = os.environ["INSTANCE_ID"]
PUBLIC_KEY_HEX = os.environ["DISCORD_PUBLIC_KEY"]

# Optional: used only for public status messages ("start/stop initiated")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")

# Best-effort in-memory cooldown (resets on cold start)
LAST_REFRESH_BY_USER: dict[str, float] = {}
REFRESH_COOLDOWN_SECONDS = int(os.environ.get("REFRESH_COOLDOWN_SECONDS", "10"))

ALLOWED_USER_IDS = {
    s.strip()
    for s in os.environ.get("ALLOWED_USER_IDS", "").split(",")
    if s.strip()
}

AMP_INSTANCE_NAME = os.environ.get("AMP_INSTANCE_NAME", "").strip()
AMPINST_PATH = os.environ.get("AMPINST_PATH", "ampinstmgr").strip()

SSM_TIMEOUT_SECONDS = int(os.environ.get("SSM_TIMEOUT_SECONDS", "120"))
SSM_POLL_SECONDS = int(os.environ.get("SSM_POLL_SECONDS", "3"))


def _h(headers, key):
    return headers.get(key) or headers.get(key.lower()) or headers.get(key.upper())


def _resp(obj, status=200):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(obj),
    }


def _mention(uid: str) -> str:
    return f"<@{uid}>" if uid else "(unknown user)"


def _discord_channel_send_embed(channel_id: str, embed: dict) -> str | None:
    """
    Send a normal channel message (public) with an embed.
    Returns error string on failure, else None.
    """
    if not channel_id or not DISCORD_BOT_TOKEN:
        return "missing channel_id or DISCORD_BOT_TOKEN"

    url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
    body = json.dumps({"embeds": [embed]}).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
            "User-Agent": "AWS-Server-Manager/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            _ = resp.read()
            return None
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.read().decode(errors='replace')}"
    except Exception as e:
        return f"{type(e).__name__}: {str(e)}"


def _get_state_and_ip():
    r = EC2.describe_instances(InstanceIds=[INSTANCE_ID])
    inst = r["Reservations"][0]["Instances"][0]
    state = inst["State"]["Name"]
    ip = inst.get("PublicIpAddress")
    return state, ip


def _panel_embed(state: str, ip: str | None, note: str | None = None) -> dict:
    return {
        "title": "🖥️ Server Control Panel",
        "description": note or "",
        "fields": [
            {"name": "Instance", "value": f"`{INSTANCE_ID}`", "inline": False},
            {"name": "Status", "value": f"**{state}**", "inline": True},
            {"name": "Public IP", "value": f"`{ip or '—'}`", "inline": True},
        ],
        "color": 0x5865F2,
    }


def _components_for_state(state: str):
    transitioning = state in ("pending", "stopping", "shutting-down")
    start_enabled = state == "stopped"
    stop_enabled = state == "running"

    return [{
        "type": 1,
        "components": [
            {
                "type": 2, "style": 3, "label": "▶ Start", "custom_id": "server_start",
                "disabled": transitioning or (not start_enabled)
            },
            {
                "type": 2, "style": 4, "label": "■ Stop", "custom_id": "server_stop",
                "disabled": transitioning or (not stop_enabled)
            },
            {"type": 2, "style": 2, "label": "↻ Refresh", "custom_id": "server_refresh", "disabled": False},
        ],
    }]


def _invoke_async(payload: dict, context):
    LAMBDA.invoke(
        FunctionName=context.invoked_function_arn,
        InvocationType="Event",
        Payload=json.dumps(payload).encode("utf-8"),
    )


def _run_ssm_shell(instance_id: str, commands: list[str], comment: str = "") -> str:
    state, _ = _get_state_and_ip()
    if state != "running":
        raise ClientError(
            {"Error": {"Code": "InstanceNotRunning", "Message": f"EC2 is {state}"}},
            "SendCommand",
        )

    resp = SSM.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        Comment=comment or "discord server control",
    )
    return resp["Command"]["CommandId"]


def _wait_ssm_command(instance_id: str, command_id: str, timeout_s: int, poll_s: int) -> tuple[str, str]:
    deadline = time.time() + timeout_s
    last_out = ""
    time.sleep(1)

    while time.time() < deadline:
        try:
            inv = SSM.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "InvocationDoesNotExist":
                time.sleep(poll_s)
                continue
            raise

        status = inv.get("Status", "Pending")
        stdout = (inv.get("StandardOutputContent") or "").strip()
        stderr = (inv.get("StandardErrorContent") or "").strip()
        if stdout or stderr:
            joined = "\n".join([s for s in [stdout, stderr] if s])
            last_out = joined[-800:]

        if status in ("Success", "Failed", "TimedOut", "Cancelled"):
            return status, last_out

        time.sleep(poll_s)

    return "TimedOut", last_out


def _user_id_from_payload(p):
    return str(
        p.get("member", {}).get("user", {}).get("id")
        or p.get("user", {}).get("id")
        or ""
    )


def _get_cmd_option(payload: dict, name: str):
    opts = payload.get("data", {}).get("options") or []
    for o in opts:
        if o.get("name") == name:
            return o.get("value")
    return None


def _post_started(channel_id: str, actor_uid: str):
    state, ip = _get_state_and_ip()
    embed = {
        "title": "🟢 Server start initiated",
        "description": f"Requested by {_mention(actor_uid)}",
        "fields": [
            {"name": "Instance", "value": f"`{INSTANCE_ID}`", "inline": False},
            {"name": "Status", "value": f"**{state}**", "inline": True},
            {"name": "Public IP", "value": f"`{ip or '—'}`", "inline": True},
        ],
        "color": 0x2ECC71,
    }
    _ = _discord_channel_send_embed(channel_id, embed)


def _post_stopped(channel_id: str, actor_uid: str):
    state, ip = _get_state_and_ip()
    embed = {
        "title": "🔴 Server stop initiated",
        "description": f"Requested by {_mention(actor_uid)}",
        "fields": [
            {"name": "Instance", "value": f"`{INSTANCE_ID}`", "inline": False},
            {"name": "Status", "value": f"**{state}**", "inline": True},
            {"name": "Public IP", "value": f"`{ip or '—'}`", "inline": True},
        ],
        "color": 0xE74C3C,
    }
    _ = _discord_channel_send_embed(channel_id, embed)


def _stop_worker(save_before_stop: bool, actor_uid: str, channel_id: str):
    """
    Async worker for stop: optionally stop AMP instance safely, then stop EC2.
    Sends ONE channel embed when EC2 stop is initiated.
    """
    if save_before_stop:
        if not AMP_INSTANCE_NAME:
            return  # no spam; stop is not attempted without a safe AMP name

        try:
            cmd_id = _run_ssm_shell(
                INSTANCE_ID,
                commands=[
                    f"sudo -u amp {AMPINST_PATH} stop {AMP_INSTANCE_NAME}",
                    f"sudo -u amp {AMPINST_PATH} status {AMP_INSTANCE_NAME} || true",
                ],
                comment=f"AMP stop {AMP_INSTANCE_NAME} before EC2 stop",
            )
            ssm_status, _out = _wait_ssm_command(INSTANCE_ID, cmd_id, SSM_TIMEOUT_SECONDS, SSM_POLL_SECONDS)
            if ssm_status != "Success":
                return  # abort EC2 stop if AMP stop failed
        except Exception:
            return

    try:
        EC2.stop_instances(InstanceIds=[INSTANCE_ID])
    except Exception:
        return

    _post_stopped(channel_id, actor_uid)


def lambda_handler(event, context):
    # Async stop worker
    if isinstance(event, dict) and event.get("_stop") is True:
        try:
            _stop_worker(
                bool(event.get("save_before_stop", True)),
                str(event.get("actor_uid", "")),
                str(event.get("channel_id", "")),
            )
        except Exception as e:
            print("stop worker error:", repr(e))
        return {"ok": True}

    headers = event.get("headers") or {}
    body = event.get("body") or ""
    raw_body = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode("utf-8")

    sig_hex = _h(headers, "X-Signature-Ed25519")
    ts = _h(headers, "X-Signature-Timestamp")
    if not sig_hex or not ts:
        return {"statusCode": 401, "body": "missing signature"}

    try:
        vk = VerifyKey(bytes.fromhex(PUBLIC_KEY_HEX))
        vk.verify(ts.encode("utf-8") + raw_body, bytes.fromhex(sig_hex))
    except (BadSignatureError, ValueError):
        return {"statusCode": 401, "body": "bad signature"}

    payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    itype = payload.get("type")

    # PING -> PONG
    if itype == 1:
        return _resp({"type": 1})

    # Slash command: /server action:...
    if itype == 2:
        cmd_name = payload.get("data", {}).get("name")
        if cmd_name != "server":
            return _resp({"type": 4, "data": {"content": f"Unknown command: {cmd_name}", "flags": 64}})

        uid = _user_id_from_payload(payload)
        channel_id = str(payload.get("channel_id", ""))

        if ALLOWED_USER_IDS and uid not in ALLOWED_USER_IDS:
            return _resp({"type": 4, "data": {"content": "Not allowed.", "flags": 64}})

        action = (_get_cmd_option(payload, "action") or "status").lower()
        save_before_stop = _get_cmd_option(payload, "save_before_stop")
        save_before_stop = True if save_before_stop is None else bool(save_before_stop)

        try:
            state, ip = _get_state_and_ip()

            # PUBLIC panel (no flags:64)
            if action == "start":
                if state == "stopped":
                    EC2.start_instances(InstanceIds=[INSTANCE_ID])
                    _post_started(channel_id, uid)
                    note = f"Starting… requested by {_mention(uid)}."
                else:
                    note = f"Instance is **{state}**. Requested by {_mention(uid)}."

                state2, ip2 = _get_state_and_ip()
                return _resp({
                    "type": 4,
                    "data": {
                        "embeds": [_panel_embed(state2, ip2, note)],
                        "components": _components_for_state(state2),
                    },
                })

            if action == "stop":
                if state != "running":
                    note = f"Instance is **{state}**. Nothing to stop. Requested by {_mention(uid)}."
                    return _resp({
                        "type": 4,
                        "data": {"embeds": [_panel_embed(state, ip, note)], "components": _components_for_state(state)},
                    })

                if payload.get("application_id") and payload.get("token"):
                    _invoke_async(
                        {
                            "_stop": True,
                            "save_before_stop": save_before_stop,
                            "actor_uid": uid,
                            "channel_id": channel_id,
                        },
                        context,
                    )

                note = f"Saving world and stopping… requested by {_mention(uid)}."
                return _resp({
                    "type": 4,
                    "data": {"embeds": [_panel_embed(state, ip, note)], "components": _components_for_state(state)},
                })

            # status
            note = f"Requested by {_mention(uid)}. Press Refresh to update."
            return _resp({
                "type": 4,
                "data": {"embeds": [_panel_embed(state, ip, note)], "components": _components_for_state(state)},
            })

        except ClientError as e:
            msg = f"AWS error: {e.response['Error'].get('Code')}: {e.response['Error'].get('Message')}"
            return _resp({"type": 4, "data": {"content": msg, "flags": 64}})

    # Button click
    if itype == 3:
        uid = _user_id_from_payload(payload)
        channel_id = str(payload.get("channel_id", ""))

        if ALLOWED_USER_IDS and uid not in ALLOWED_USER_IDS:
            return _resp({"type": 4, "data": {"content": "Not allowed.", "flags": 64}})

        cid = str(payload.get("data", {}).get("custom_id") or "")

        try:
            if cid == "server_refresh":
                now = time.time()
                last = LAST_REFRESH_BY_USER.get(uid, 0)
                if now - last < REFRESH_COOLDOWN_SECONDS:
                    wait = int(REFRESH_COOLDOWN_SECONDS - (now - last) + 0.999)
                    return _resp({"type": 4, "data": {"content": f"Refresh cooldown. Try again in {wait}s.", "flags": 64}})
                LAST_REFRESH_BY_USER[uid] = now

                state, ip = _get_state_and_ip()
                note = f"Refreshed by {_mention(uid)}."
                return _resp({
                    "type": 7,
                    "data": {
                        "embeds": [_panel_embed(state, ip, note)],
                        "components": _components_for_state(state),
                    },
                })

            if cid == "server_start":
                state, ip = _get_state_and_ip()
                if state == "stopped":
                    EC2.start_instances(InstanceIds=[INSTANCE_ID])
                    _post_started(channel_id, uid)
                    note = f"Starting… requested by {_mention(uid)}."
                else:
                    note = f"Instance is **{state}**. Requested by {_mention(uid)}."

                state2, ip2 = _get_state_and_ip()
                return _resp({
                    "type": 7,
                    "data": {
                        "embeds": [_panel_embed(state2, ip2, note)],
                        "components": _components_for_state(state2),
                    },
                })

            if cid == "server_stop":
                state, ip = _get_state_and_ip()
                if state != "running":
                    note = f"Instance is **{state}**. Nothing to stop. Requested by {_mention(uid)}."
                    return _resp({
                        "type": 7,
                        "data": {
                            "embeds": [_panel_embed(state, ip, note)],
                            "components": _components_for_state(state),
                        },
                    })

                if payload.get("application_id") and payload.get("token"):
                    _invoke_async(
                        {
                            "_stop": True,
                            "save_before_stop": True,
                            "actor_uid": uid,
                            "channel_id": channel_id,
                        },
                        context,
                    )

                note = f"Saving world and stopping… requested by {_mention(uid)}."
                return _resp({
                    "type": 7,
                    "data": {
                        "embeds": [_panel_embed(state, ip, note)],
                        "components": _components_for_state(state),
                    },
                })

            return _resp({"type": 7, "data": {"content": f"Unknown action: {cid}", "components": []}})

        except ClientError as e:
            msg = f"AWS error: {e.response['Error'].get('Code')}: {e.response['Error'].get('Message')}"
            return _resp({"type": 7, "data": {"content": msg, "components": []}})
        except Exception as e:
            return _resp({"type": 7, "data": {"content": f"Error: {type(e).__name__}", "components": []}})

    return _resp({"type": 4, "data": {"content": f"Unhandled interaction type: {itype}", "flags": 64}})
