# PHP2Shell

PHP2Shell is a small Python tool that checks websites for PHP version information that may indicate exposure to **CVE-2026-109618** and **CVE-2026-109619**.

It reads normal HTTP responses. It does not exploit the vulnerabilities or execute code.

## Requirements

- Python 3.9+
- No extra packages needed

## Install

```bash
git clone https://github.com/ChrishSec/PHP2Shell.git
cd PHP2Shell
```

## Usage

Scan one URL:

```bash
python3 scanner.py -u https://example.com
```

Scan a list of targets (one host or URL per line):

```bash
python3 scanner.py -l subdomains.txt
```

You can also pass the filename directly:

```bash
python3 scanner.py subdomains.txt
```

Check linked pages or specific paths:

```bash
python3 scanner.py -l subdomains.txt --crawl
python3 scanner.py -l subdomains.txt --path /admin --path /login
```

Save the results as JSON:

```bash
python3 scanner.py -l subdomains.txt -o results.json
```

Run `python3 scanner.py --help` to see all options.

## Results

- `POTENTIALLY_VULNERABLE` — the detected PHP version falls in a range the scanner flags. Check the server package and vendor patches.
- `PATCHED_UPSTREAM` — the detected version meets the upstream fix level used by the scanner.
- `INCONCLUSIVE` — the version could not be classified.
- `VERSION_NOT_DISCLOSED` — PHP appears to be in use, but no version was found.
- `NO_PHP_BANNER` — no PHP version was found in the headers checked.
- `ERROR` — the request could not be completed.

## A note about results

PHP2Shell only sees information exposed by the website. A proxy or server configuration can hide or change the PHP version, and vendors sometimes backport fixes without changing the version number. A scan result is a starting point, not proof that a server is vulnerable or patched. Check the installed PHP package and the vendor's advisory to confirm.

## References

- [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP security advisories](https://www.php.net/security/)

## License

GPL-3.0. See [LICENSE](LICENSE).

## Author

Made by [ChrishSec](https://github.com/ChrishSec).
