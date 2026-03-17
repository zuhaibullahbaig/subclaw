# SubClaw

Scan a list of subdomains (from subfinder or any other tool), check DNS records, HTTP status, archived URLs, and easily mark the ones you find interesting.

## Features

- Support for subfinder output files
- `--domain` flag to automatically run subfinder
- DNS lookup (dig / nslookup)
- HTTP status check (built-in or curl)
- Archive URLs via waybackurls or gau (max 10)
- Optional port scanning with masscan or nmap
- `--raw` mode to see original tool output
- Single key interaction (`y` = save full report, any other key = skip)
- Beautiful colored output + doctor command

## Installation

**One-command install:**

```bash
curl -fsSL https://raw.githubusercontent.com/zuhaibullahbaig/subclaw/main/install.sh | bash
```

**Manual install:**

```bash
git clone https://github.com/zuhaibullahbaig/subclaw.git
cd subclaw
chmod +x subclaw.rb
sudo cp subclaw.rb /usr/local/bin/subclaw
```

## Usage

```bash
# Basic usage with subfinder output file
subclaw subfinder_output.txt

# Auto discover subdomains for a domain
subclaw --domain example.com

# With custom tools
subclaw --domain example.com --dns nslookup --urls gau --http curl --ports nmap

# Raw output mode
subclaw --domain example.com --raw

# Check dependencies
subclaw doctor

# Help
subclaw --help
```

## Examples

```bash
# Most common way
subclaw --domain target.com

# Using gau instead of waybackurls
subclaw --domain target.com --urls gau

# Full power mode
subclaw --domain target.com --dns nslookup --urls gau --http curl --ports nmap --raw
```

## Developed by

**Zuhaib Ullah Baig**  
GitHub: [https://github.com/zuhaibullahbaig](https://github.com/zuhaibullahbaig)

**Grok**  
Website: [https://grok.com](https://grok.com)

Star the repo if it helps you speed up your recon! 🔥