# Link Verifier

A Python CLI that checks whether a URL is legitimate, safely reachable, and not pointing to local/internal infrastructure.

## Features

- Validates URL syntax
- Allows only `http` and `https`
- Rejects `localhost`, private IPs, and local/internal hosts
- Resolves DNS and checks for suspicious private/reserved addresses
- Detects unsafe redirects when an allowlist is used
- Supports CLI usage and Python import usage

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m link_verifier.cli https://example.com
python -m link_verifier.cli https://github.com github.com
python -m link_verifier.cli http://localhost:8000
```

You can also install the package in editable mode:

```bash
pip install -e .
link-verifier https://example.com
```

## Example Output

```text
URL: https://www.google.com
Status: OK
Legit: True
Message: Link is reachable and valid.
Final URL: https://www.google.com/
```

## Python API

```python
from link_verifier import validate_link

result = validate_link("https://example.com")
print(result)
```

## Notes

This tool is intentionally conservative. It is best used as a safety check before trusting external links in automation or AI workflows.
