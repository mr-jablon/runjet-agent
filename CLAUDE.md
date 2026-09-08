# CLAUDE.md

Guidance for Claude Code (and developers) working in this repository.

## What this is

The **Runjet agent**: the program that runs jobs scheduled in Runjet, on the
customer's own machine. One Go module, `github.com/mr-jablon/runjet-agent`, at
the root of this repository. `README.md` is the product description and is
written for somebody who arrived from GitHub and has never seen Runjet.

The control plane lives in a separate, private repository. **Nothing here may
depend on it.** The dependency runs the other way: the server imports
`protocol/` and `signing/` from this module, because the agent has to build
from a tree the control plane is not in.

## Rules that hold inside this repository

Each of these fails quietly if broken, which is why they are written down.

- **Commit messages are in English.** The control plane's repository writes
  them in Czech; this one is public, or will be, and is read by people who
  arrived from GitHub. Same seam the manual and the e2e suite already draw.
- **No dependency outside the standard library.** `go.mod` having no `require`
  block is a property, not a coincidence: this binary is copied onto machines
  nobody at Runjet can reach, and every dependency is one more thing an
  operator has to trust and one more reason for it to stop building on an older
  toolchain. Adding one is a decision, not a convenience.
- **`protocol` changes are additive, or built per version.** The server serves
  a *window* of versions and answers an agent in the version that asked. An
  agent in the field is upgraded by somebody else, on their own day; a change
  that is neither additive nor versioned is an outage at every customer who has
  not acted, and the symptom is "nothing happened".
- **`runner` is a public package on purpose.** It is the only place in the
  whole product where a process is started, and one day somebody will want to
  read it without reading the rest.
- **`signing` and `protocol` stay two packages.** Merging them would be tidier
  and would rename every `signing.Envelope` in the control plane for nothing.
- **A job runs as its own account, and that is the whole of the isolation.**
  A file cannot be hidden from a process sharing its uid, so nothing else can
  achieve it. The tests that prove it need the privilege to change uid and skip
  everywhere else — see below. They are the only check on the property
  everything else is layered on.

## Commands

```bash
go build .                       # this host
go test ./...                    # the suite; uid tests skip without privilege
go vet ./... && gofmt -l .       # static checks and formatting
./build.sh v1.2.3                # static binaries for all four platforms
```

The tests that need to change uid skip on a developer's machine, which on macOS
means always. Run them on Linux as root — this is what CI does, and it is not
optional before a release:

```bash
sudo go test ./... -count=1
```

## Working on the protocol together with the control plane

Both halves at once needs a `go.work` **one directory above both checkouts**:

```
go 1.25.0

use (
	./runjet/backend
	./runjet-agent
)
```

**It must name both.** A workspace that lists only the control plane switches
off vendoring in it and then has nowhere to take this module from; the error
reads as a broken checkout rather than as a missing line.

## Releasing

A tag `v1.2.3` on `main` builds four static binaries, writes `SHA256SUMS` and
publishes the Release. Three things are load-bearing:

- **The asset names are a contract** with the manual, which prints
  `releases/latest/download/runjet-agent-<goos>-<goarch>` and `SHA256SUMS`.
  This repository may change how it builds, but not those five file names.
- **The version reaches the binary through ldflags.** Without it the agent
  reports `dev`, and the agent list in Runjet — which compares each agent's
  build against the server's, and is the only warning a customer gets before
  the protocol window moves past them — starts reading as nonsense.
- **The tag must sit on `main`.** GitHub cannot filter a tag trigger by branch,
  so the workflow checks it as a job.

Binaries, and only binaries. There is no `Dockerfile` here and there should not
be one: the agent is a static file you drop on a host, the licence permits
building it from this source but not shipping the result on, and an image in
the tree invites both a distribution channel nobody maintains and a second way
to run it that the manual would have to keep describing.
