# cleanrepo (fixture)

Hardened twin of `labs/vulnrepo`: same endpoints, correctly written. Used as
the negative control for `libella.codeaudit` — it must yield zero code
findings and no dependency observations while every pin is patched.
