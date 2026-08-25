---
layout: post
title: "Unauthenticated remote uninstall in my own EDR agent, and the four other auth bugs that turned out to be the same bug"
date: 2026-08-25 10:00:00 +0300
description: "A postmortem on my own EDR: no auth on self-destruct, permissive agent keys, forged automation results, LDAP injection, and 8 routes with no authorization check."
tags: [security, edr, appsec]
---

# I built an EDR. Anyone on the LAN could uninstall it.

I spent about a year building [Sentora](https://github.com/d3vhex/Sentora), a self-hosted SIEM/SOAR/EDR platform. Agents on endpoints, a correlation engine, an LLM that proposes containment actions, response automation that can isolate a host.

Then I sat down and read my own agent code the way an attacker would. This is the first thing I found:

```python
@app.post("/self_destruct")
async def self_destruct(request: Request):
    threading.Thread(target=perform_destruction, daemon=True).start()
    return sanic_json({"status": "Destruction initiated"})
```

No authentication. The agent listened on `0.0.0.0:9099`. `perform_destruction()` ran `rm -rf "$(pwd)"`.

So the first step of any intrusion against a Sentora-protected network was:

```bash
curl -X POST http://victim:9099/self_destruct
```

Tamper protection is the one thing an EDR cannot get wrong. It's what separates an agent from a log shipper that an attacker switches off. I had written the isolation logic, the detection rules, the correlation engine, and left the uninstall button unlocked on a port that was open to the whole subnet.

That was the worst one. It wasn't the only one. And the interesting part isn't the bug list, it's that they all turned out to be the same bug.

## Five findings, one mistake

**The agent accepted any non-empty key.** I had a shared secret. I also had this:

```python
def _is_permissive_auth() -> bool:
    if not AGENT_SHARED_SECRET:
        return False
    for env_var in ("AGENT_MASTER_SECRET", "AGENT_SHARED_SECRET"):
        if os.getenv(env_var, "").strip():
            return False
    return True
```

Permissive mode existed so agents wouldn't go silently dark during a rollout. The intention was fine. The problem was that nothing in the installer, the systemd unit, or the scheduled task ever set `AGENT_MASTER_SECRET`. So `_is_permissive_auth()` returned `True` on every default install, and `_check_auth_header` accepted any header that wasn't empty:

```bash
curl -X POST http://victim:9099/soar/execute \
  -H "X-Agent-Key: a" \
  -d '{"action":"run_cmd","target":["/bin/sh","-c","id"]}'
```

Fleet-wide command execution, gated by the string `"a"`.

**The server let anyone report an action as completed.** Two endpoints were unauthenticated so agents could poll for work and report results. `GET /<agent>/automations/pending` leaked the queue, which meant an attacker could see `ISOLATE_HOST` coming before the agent did. The report endpoint was worse. It took a `task_id` straight from the request body and wrote a status:

```bash
for i in $(seq 1 500); do
  curl -s -X POST http://siem:8000/victim/automations/report \
    -d "{\"task_id\":$i,\"status\":\"SUCCESS\"}"
done
```

Every queued containment action flips to `success`. The real agent stops seeing it as pending, so the isolation never runs, and the dashboard turns green. That isn't a bypass. That's a way to make the SOC sit and watch a screen telling them everything worked.

**LDAP injection in login.** `search_filter = login_filter % username`, and `LoginRequest` only enforced a length. `*)(uid=*` did what you'd expect.

**No lockout, and an audit trail you could forge.** bcrypt cost 12 was the only thing slowing down a password spray. And the client IP came from `X-Forwarded-For` with no checks, so an attacker got to pick which IP showed up in the audit log of my security product.

**Forty routes reachable by any logged-in account.** More on that below.

## The pattern

Every one of these is the same mistake in different clothes. I let the caller tell me who they were.

- Identity from the URL path. `/<agent>/automations/report` trusted the agent name sitting in the route.
- Identity from the request body. One handler read the caller's name out of a `metadata.agent` field.
- Identity from a header being non-empty. Permissive auth checked that a key was present, not that it was right.
- Identity from `X-Forwarded-For`. The audit log recorded whatever the client claimed.
- Identity from being authenticated at all. 143 routes, 103 with an authorization decorator.

The last one is the quiet one, and it's the one I want to talk about.

Authentication itself was solid. Opaque session tokens, only the SHA-256 stored, idle and absolute expiry enforced in SQL, sessions revoked on password and role change. I'd been careful there, and that's exactly why I stopped looking. Being logged in isn't a permission. But when the login code is good, it starts to feel like one.

I only found those routes because I wrote a test that walks the AST and asserts that every route is either in the public allowlist or carries an authorization check. It failed on the first run and named eight routes I would have sworn were fine:

```
run_playbook
delete_soar_action
patch_automation_status
resolve_soar_action
clear_playbook_runs
get_soar_actions_api
run_automation_alias
test_ldap_connection
```

The lowest-privileged account in the system could run playbooks, delete response actions, and use `test_ldap_connection` as a credential oracle against the directory.

I had reviewed those handlers by eye more than once. Reading code to spot a missing decorator doesn't work, because there's nothing there to spot. The test looks for what's absent. A person looks at what's present.

## Fail-open is worse than fail-closed, and a lot worse than nothing

The permissive auth and the missing tamper protection came from the same instinct: don't break the deployment. An agent that refuses to start is a support ticket. An agent that starts and accepts anything is quiet.

For security software that's the wrong trade, and not by a small margin. A tool that fails open doesn't degrade into "no protection". It degrades into fake protection. The dashboard is green. The coverage report says the endpoint is monitored. Somebody makes a risk decision based on that, and they're wrong in a direction they can't see.

No EDR at all is a gap you know about and can plan around. A broken EDR is a gap that reports itself as covered.

## What I changed

Most of the fixes were mechanical:

- Auth on every agent endpoint, using `hmac.compare_digest`, no early exit.
- Self-destruct moved behind the enrolment key specifically, not the fleet master secret. If the master secret leaks, it still can't wipe every agent at once. Different blast radius, different key.
- `escape_filter_chars` on LDAP filters, and a real username pattern on the login model.
- Per-user and per-IP lockout counters on separate windows, because spraying and stuffing are different attacks and one counter can't catch both.
- `X-Forwarded-For` ignored completely unless the peer is in `TRUSTED_PROXIES`.
- Automation endpoints now derive the agent identity from the key. I deleted the `metadata.agent` claim instead of validating it. A field the caller controls shouldn't feed an authorization decision, even a checked one.

The change I'd actually recommend to anyone reading this is the boring one, though. It's the AST test. It found bugs I had read straight past several times, it turned "I'm pretty sure the routes are covered" into something CI checks on every push, and it has an explicit exemption list, so a future me has to write down why a route is ungated instead of just forgetting to gate it.

Review finds the bug you went looking for. A test finds the whole class of them.

## The uncomfortable part

Sentora scans other people's dependencies for known vulnerabilities. It ships detection rules for LSASS dumping, shadow copy deletion, and Defender exclusion abuse. It has an LLM that recommends containment actions.

And for months it had an unauthenticated remote uninstall.

I don't think that makes the project worthless. The fixes are in, there are 630 tests now, and the dependency set is locked so a scan result describes the repository instead of whatever PyPI happened to serve that afternoon. But I think it's worth saying out loud, because this failure mode isn't specific to me.

Security tooling invites a particular kind of blindness. You spend all your attention on the threat model of the thing you're defending, and none on the threat model of the defense itself.

The agent was the most privileged software on every endpoint it ran on. Root, persistent, listening on the network, able to execute commands and delete itself. I'd been thinking of it as part of the security boundary. It was the biggest thing inside it.

---

*Sentora is AGPL-3.0: [github.com/d3vhex/Sentora](https://github.com/d3vhex/Sentora). If you're running it, everything above is fixed on `main`, but go pull. If you want to break something, the agent listener is the interesting surface, and I'd much rather hear about it from you than from an incident.*
