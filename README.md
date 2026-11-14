# PHP2Shell Scanner

Passive PHP version scanner for **CVE-2026-109618** and **CVE-2026-109619**. Supports single URLs, subdomain lists, and crawling.

## Usage

Requires Python 3.9 or newer. No extra packages needed.

Scan one URL:

```bash
python3 scanner.py -u https://example.com
```

Scan a list of subdomains (`subdomains.txt`, one per line):

```bash
python3 scanner.py -l subdomains.txt
```

Follow links and check other pages:

```bash
python3 scanner.py -l subdomains.txt --crawl
```

Check a specific path:

```bash
python3 scanner.py -l subdomains.txt --path /admin
```

## Disclaimer

This tool is intended for educational and security research purposes only. Use it only on systems you own or have permission to test.

The author is not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the **GNU General Public License v3.0**.

See the [GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.en.html) for details.

## Author

Developed by [ChrishSec](https://github.com/ChrishSec).

Feel free to fork, modify, or contribute.

Contact: [Telegram](https://t.me/ChrishSec)
