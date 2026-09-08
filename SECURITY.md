# Reporting a security problem

This program runs as a system service, usually as `root`, on machines we cannot
reach. Please do not open a public issue for a security problem in it.

**Write to security@runjet.dev.** Include what you found, how to reproduce it,
and which agent version you are running — the agent has no flag that prints it,
so take it from the binary you installed, or from the agent list in Runjet,
which shows what each host reported. If you would like a reply encrypted, say
so and we will arrange it.

We will acknowledge within three working days, tell you what we think within
ten, and let you know when a fix is released. We will credit you by whatever
name you ask for, or not at all.

## What is in scope

Anything in this repository, and any binary from a release here. The things we
care about most, because everything else is layered on them:

- a job reading the agent's private key or its secrets file,
- a job escaping the account it was meant to run as,
- a dispatch being accepted without a valid signature from the workspace key,
- an agent's identity or enrolment token being usable by somebody else.

## What is not

The control plane and the dashboard are a different codebase; report those to
the same address, but they are not this repository.

**A job harming the host it runs on is not a vulnerability.** The agent runs
the commands you give it. Running jobs under their own account keeps them away
from the agent's own secrets — it is not a sandbox, and a job has a shell.
