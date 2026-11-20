# Acknowledgments

## Inspiration

This project started as a review of **[secret-scanner](https://github.com/mercury0993/secret-scanner)** by [@mercury0993](https://github.com/mercury0993), a Claude Code skill that asks the agent to search a codebase for secrets, key files, environment files and PII before a commit. Its idea and its categories of checks shaped this project, and that credit belongs to its author.

secret-preflight is an independent rewrite, not a fork. It reuses none of the original's text or report format. It differs in approach:

- Detection moved from agent-run grep into a masking script, so raw values never reach the model.
- Scope is defined by git (`staged`, `push`, `tree`) instead of the whole directory.
- There is a CRITICAL level for secrets already pushed, with rotation as the first action.
- PII is reported only after checksum validation, and false-positive filtering applies to values instead of whole lines.
- The report is a verdict-first go/no-go format with a mandatory coverage section.
- A self-test suite is included.

The original repository did not include a license when this project was created. No code or prose from it has been copied here.

## Prior art and references

- [gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog): the reference open-source secret scanners. Use them for full-history audits; the skill offers them as a second opinion when installed.
- [git-filter-repo](https://github.com/newren/git-filter-repo): recommended in `references/remediation.md` for history rewrites.
- Token formats come from the providers' public documentation of their key prefixes.
- Validation algorithms: Luhn (ISO/IEC 7812) for payment cards, ISO 13616 mod-97 for IBANs, ISO 7064 MOD 11-2 for Chinese resident ID numbers, and the mod-97 check of the Belgian national register number.

## Authorship

Designed and maintained by [Medenor](https://github.com/Medenor), with the help of Claude (Anthropic).
