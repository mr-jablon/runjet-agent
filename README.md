# Runjet agent

The agent runs the jobs you schedule in [Runjet](https://runjet.dev). It is one
static binary. There is nothing to install around it — no runtime, no libc
version it has to agree with — because it is meant to be copied onto machines
you do not otherwise manage.

It opens no port. It dials out to Runjet over HTTPS, asks whether there is work,
runs it, and reports back. Nothing needs to reach in.

## Why this is a separate program

**Runjet does not run your code.** The control plane schedules, records and
shows you what happened; the command itself only ever executes here, on your
host, under an account you chose. That is not a policy the server promises to
keep — its own image is distroless and has no shell, so it *cannot* start a
process. This repository is the other half, and it is the only place in Runjet
where a process is ever started.

That split is why the agent is versioned, released and downloaded on its own.
You upgrade it when it suits the machine it is on, not when Runjet ships.

## Install

Full instructions, including the systemd unit and the two accounts, are in the
manual: **[docs.runjet.dev/agents/install](https://docs.runjet.dev/agents/install)**.
The short version, on a Linux host:

```bash
curl -fsSLO https://github.com/mr-jablon/runjet-agent/releases/latest/download/runjet-agent-linux-amd64
curl -fsSLO https://github.com/mr-jablon/runjet-agent/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
install -m 0755 runjet-agent-linux-amd64 /usr/local/bin/runjet-agent
```

Every release carries four binaries — `linux-amd64`, `linux-arm64`,
`darwin-amd64`, `darwin-arm64` — and the checksums for all of them.
`--ignore-missing` is there because you downloaded one of the four.

Then enrol it. In Runjet, **Agents → Register agent** produces the whole
command, with your workspace's public key and a one-time token in it:

```bash
runjet-agent enroll \
  -url https://runjet.dev \
  -key sched-1:BASE64KEY \
  -token ONE-TIME-TOKEN
```

The token appears in the host's process list while that runs; `-token-file`, or
feeding it on stdin, avoids even that.

It writes `/etc/runjet-agent/agent.env`, generates the host's keypair, spends
the token and never needs it again. From then on the agent authenticates by
signing its requests, and Runjet verifies dispatches with the workspace key —
so neither side is trusting a bearer secret over the wire.

## Configure

`deploy/agent.env.example` is the reference and the one place worth reading;
it documents every setting with the reason it exists. `deploy/runjet-agent.service`
is the systemd unit.

## What a job can reach

Deliberately narrow, and the three parts are independent.

**It runs as its own account.** `AGENT_JOB_USER` (default `runjet-job`) is not
the account the agent runs as, so the agent's private key and its secrets file
are unreadable to the commands it starts. Nothing else achieves this: a file
cannot be hidden from a process that shares its uid.

**Its environment is built, not inherited.** A job gets `PATH`, `HOME`, `USER`,
`LOGNAME`, `SHELL`, `TZ`, `LANG`, `LC_*`, whatever `AGENT_PASS_ENV` names, and
the secrets it declared. Nothing else. A setting added to the agent later cannot
leak into a job by default.

**Secret values are masked in the output** before it leaves the host. That is a
net for `set -x` and `curl -v`, not a boundary — `base64` walks straight past
it.

Running the agent somewhere that cannot change uid — a container started as a
non-root user, a hardened kernel — costs you the first of the three. Changing
uid needs `CAP_SETUID`, and a non-root process does not get that from
`--cap-add`. Set `AGENT_JOB_USER=` (empty) there and jobs run as the agent,
which means they can read its key and its secrets file; the agent warns about
it at every start, and refuses to start if it was told to isolate and cannot.

## Versions

The agent does not have to match the server. Runjet serves a *window* of
protocol versions and refuses only what falls outside it, because the two halves
are upgraded by different people on different days — an agent that had to match
would mean every Runjet release stopping every customer's jobs until each of
them acted.

The agent list in Runjet says when an agent is approaching the edge of that
window. That is the warning to act on; until then, upgrading is optional.

## Build it yourself

Go 1.25 or newer, and nothing else — the agent has no dependency outside the
standard library, and `go.mod` having no `require` block is a property worth
keeping rather than a coincidence.

```bash
go build .            # this host
./build.sh v1.2.3     # static binaries for all four platforms, into dist/
go test ./...         # the suite
```

A few tests need the privilege to change uid — the ones proving a job runs as
`runjet-job` and cannot read the agent's key. They skip without it, which on
macOS means always. On a Linux host, as root:

```bash
sudo go test ./... -count=1
```

That is the only check on the property everything else is layered on, so it is
worth running somewhere it does not skip. CI runs it on every push.

## Releasing

A tag `v1.2.3` builds the four binaries, writes `SHA256SUMS` and publishes the
Release. The tag must be on `main`; the workflow checks. The version in the tag
is stamped into the binary and is what the agent reports to Runjet, so a build
without it would make the agent list stop meaning anything.

## Licence and security

Source-available, not open source: see [LICENSE](LICENSE), or
[LICENSE-cz](LICENSE-cz) for the Czech wording, which prevails where the two
differ. You may read the source, build it, run its tests, and run what you
build against your own Runjet account; you may not ship it on. Third-party
notices are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) — there is one
entry, and it is the Go standard library.

To report a security problem, see [SECURITY.md](SECURITY.md) — this is a
program that runs as root on machines we cannot reach, so please do not open a
public issue for one.
