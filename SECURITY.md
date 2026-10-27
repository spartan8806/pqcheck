# Security policy

## Reporting a vulnerability in pqcheck

Please report suspected vulnerabilities privately to the maintainers
(coordinated disclosure) rather than opening a public issue, and allow
a reasonable remediation window before publishing details.

A useful report:

1. **Verifies by execution.** Include the exact commands or script that
   reproduce the behaviour in this repository, with versions pinned
   (commit or release — never a moving reference).
2. **Leads with the reproducer.** The smallest target, manifest, and
   relation invocation that demonstrates the problem comes first, not
   last.
3. **States the ceiling.** Say what the report establishes and what it
   does not establish. A relation detecting a defect does not by itself
   establish exploitability, severity, or impact on other versions.
4. **Never overclaims severity.** Distinguish a confirmed functional
   defect (e.g. a signature that verifies under the wrong key) from a
   lead (e.g. a timing separation that must be re-measured on isolated,
   frequency-pinned hardware before it means anything).

## In-scope security bugs in pqcheck itself

**False reassurance is a security bug in this tool.** A
`NO_DEFECT_FOUND` (or an exit code of `0`) produced for a surface that
was never actually exercised — a harness that was never opened, a
positive control that failed, a relation that made zero target calls, a
witness search that found nothing being read as clean — defeats the
tool's purpose and is treated with the same seriousness as a missed
defect. So is any path that lets secret-shaped material (keys, shared
secrets) leak into a claim or report, since pqcheck reports are meant
to be pasted into public bug trackers.

False *defects* on correct implementations are also security-relevant:
they send maintainers hunting bugs that do not exist and train users to
ignore the tool. The adversarial precision suite in
`pqcheck/testing/precision.py` exists to keep those from shipping.

## Scope

pqcheck is a local diagnostic for code you are authorised to test. It
opens only targets named by a local manifest or folder, never scans
networks, and its reports must never contain keys, shared secrets, or
anyone else's credentials. Vulnerabilities in third-party PQC libraries
that you find *with* pqcheck should be disclosed to those projects
under their own policies — the guidelines above describe the report
shape those projects will want.
