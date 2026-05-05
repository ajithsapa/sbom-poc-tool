# handson-ml — example fixture

Sample ML project with vulnerable dependency pins, used by the SBOM tool's
default Swagger example.

Scanning this directory surfaces 5 CVEs against the seeded NVD cache:

| CVE | Package | CVSS | Severity |
|-----|---------|------|----------|
| CVE-2022-21797 | `joblib==0.14.1` | 9.8 | High |
| CVE-2022-29216 | `tensorflow==1.15.5` | 8.8 | High |
| CVE-2023-44271 | `Pillow==9.0.1` | 7.5 | High |
| CVE-2021-33430 | `numpy==1.22.0` | 5.5 | Medium |
| CVE-2023-25399 | `scipy==1.6.0` | 5.5 | Medium |

This is an isolated dependency manifest — there is no source code, dataset, or
notebook here. The SBOM tool inventories declared dependencies, not installed
packages, so a `requirements.txt` is sufficient for a complete scan.

To scan it from the repository root:

```bash
sbom-tool scan --repo ./examples/handson-ml-fixture --format cyclonedx
```
