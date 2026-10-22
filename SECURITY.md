# Security Policy

SpectraScan is a network reconnaissance and security-assessment toolkit. Its active probes can affect systems, generate alerts, or expose sensitive asset information. Use it only within an explicitly authorized scope.

## Supported versions

This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The current \`main\` branch documents version 2.2.0. A supported version does not mean every optional module is free of defects; apply updates and validate findings before acting on them.

| Version line | Security support | Notes |
|---|---|---|
| **2.2.x** | ✅ Current | Preferred line; security fixes and compatible patches |
| **2.1.x** | ⚠️ Best effort | Upgrade to 2.2.x where possible |
| **2.0.x and earlier** | ❌ Unsupported | Upgrade before relying on security fixes |

Only versions explicitly published as releases should be treated as official release artifacts. The version documented on \`main\` may be ahead of a tagged release.

## Reporting a vulnerability

Please report suspected vulnerabilities privately:

**Email:** [wanheda.work@gmail.com](mailto:wanheda.work@gmail.com)

Do not disclose exploitable details in a public issue or pull request before coordinating a fix. Do not test a suspected issue against systems you do not own or have permission to assess.

Include, where practical:

- Affected version, commit, operating system, and Python version
- The relevant module/command and concise reproduction steps
- Expected versus actual behavior and potential impact
- Minimal proof-of-concept output, with credentials, tokens, personal data, and sensitive target details removed
- A suggested mitigation, if known

Do not include live secrets or unnecessary personal or third-party data in the report.

## Response process

We aim to acknowledge reports within **48 hours** and provide an initial assessment or next steps within **72 hours**. These are response targets, not a guarantee of a fix within that period. Severity, reproducibility, and maintainer availability may affect the remediation timeline.

## Security expectations for users

- Obtain authorization and define permitted targets before scanning.
- Treat banners, hostnames, IPs, paths, and scan reports as potentially sensitive.
- Keep API keys and credentials in environment variables or a secrets manager; never commit them.
- Use explicit target limits, exclusions, timeouts, and concurrency caps. Do not interpret a timeout or UDP silence as proof that a service is safe or closed.
- Treat CVE matches as leads unless product identity, version range, configuration, and advisory evidence support a stronger conclusion.
- Keep dependencies updated and review the changelog when upgrading.

## Scope

This policy covers security defects in SpectraScan code and its documented packaging/configuration. It does not authorize testing third-party systems, guarantee that external data providers are accurate, or replace the security policies of dependencies and external services.

Thank you for reporting responsibly and helping improve SpectraScan.
