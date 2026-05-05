# TaskMatrix — example fixture

LLM/agent project with vulnerable `langchain` pin, used to demonstrate the
SBOM tool against AI ecosystem dependencies.

Scanning this directory surfaces 4 CVEs against the seeded NVD cache:

| CVE | Package | CVSS | Severity |
|-----|---------|------|----------|
| CVE-2023-34540 | `langchain==0.0.101` | 9.8 | High |
| CVE-2023-44271 | `Pillow==9.0.1` | 7.5 | High |
| CVE-2023-32681 | `requests==2.27.1` | 6.1 | Medium |
| CVE-2021-33430 | `numpy==1.22.0` | 5.5 | Medium |

To scan it from the repository root:

```bash
sbom-tool scan --repo ./examples/TaskMatrix-fixture --format cyclonedx
```
