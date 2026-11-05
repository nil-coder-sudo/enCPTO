# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.
Use GitHub's [private vulnerability reporting](https://github.com/nil-coder-sudo/enCPTO/security/advisories/new)
and include the version, platform, and steps or a sample file that reproduce the problem.

## Scope

In scope: anything that lets an attacker read, forge or silently alter container contents, recover keys or
plaintext from memory or disk, or make the app write outside the chosen output folder.

Out of scope: weak passwords chosen by the user, and data remanence after shredding on SSDs or
copy-on-write / journaling file systems (documented limitation).

## Supported versions

Only the latest release receives fixes.
