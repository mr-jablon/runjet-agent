# Third-party notices

This file is the list referred to in Article 5 of the License
(`LICENSE`, `LICENSE-cz`).

The Runjet Agent has **no dependency outside the Go standard library**.
`go.mod` carries no `require` block and there is no `go.sum`, which is a
deliberate property rather than a coincidence: this binary is copied
onto machines nobody at Runjet can reach, and every dependency would be
one more thing an operator has to trust.

That leaves exactly one third-party component, and it reaches you inside
the binary rather than beside it:

## The Go standard library and runtime

Official Builds are produced with `CGO_ENABLED=0`, so they are fully
static — the Go standard library and runtime are linked into every
released binary. They are distributed by The Go Authors under the
three-clause BSD license, with an additional patent grant. Both texts
are reproduced below, unmodified, from the Go distribution the binaries
are built with.

- Component: the Go standard library and runtime (`golang.org/x/…` is
  not used)
- Source: https://go.dev/, https://github.com/golang/go
- License: BSD 3-Clause, plus the Additional IP Rights Grant (Patents)

### LICENSE

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### PATENTS

```
Additional IP Rights Grant (Patents)

"This implementation" means the copyrightable works distributed by
Google as part of the Go project.

Google hereby grants to You a perpetual, worldwide, non-exclusive,
no-charge, royalty-free, irrevocable (except as stated in this section)
patent license to make, have made, use, offer to sell, sell, import,
transfer and otherwise run, modify and propagate the contents of this
implementation of Go, where such license applies only to those patent
claims, both currently owned or controlled by Google and acquired in
the future, licensable by Google that are necessarily infringed by this
implementation of Go.  This grant does not include claims that would be
infringed only as a consequence of further modification of this
implementation.  If you or your agent or exclusive licensee institute or
order or agree to the institution of patent litigation against any
entity (including a cross-claim or counterclaim in a lawsuit) alleging
that this implementation of Go or any code incorporated within this
implementation of Go constitutes direct or contributory patent
infringement, or inducement of patent infringement, then any patent
rights granted to you under this License for this implementation of Go
shall terminate as of the date such litigation is filed.
```

## Checking this list

The list is short enough to verify yourself, and the CI does on every
push:

```bash
go list -deps ./...
```

Everything it prints is either a package of the Go standard library or
one of this module's own packages under `github.com/mr-jablon/runjet-agent`.
Anything else appearing there means this file is out of date.
