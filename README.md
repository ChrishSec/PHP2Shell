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

Check a specific path, such as a login page:

```bash
python3 scanner.py -l subdomains.txt --path /admin
```

## Disclaimer

This tool is intended for educational and research purposes only. Use it at your own risk. The author is not responsible for any damage caused by the use or misuse of this tool.

Only scan websites you own or have permission to test.

## License

This tool is released under the **GNU General Public License v3.0**. Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed.

See the [GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.en.html) for details.

## Author

This tool was developed by [ChrishSec](https://github.com/ChrishSec). Feel free to fork, modify, and distribute it. If you have any questions or suggestions, please reach out to the author on [Telegram](https://t.me/ChrishSec).
