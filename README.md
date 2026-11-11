# Python Nmap Network Scanner

A Python program that reads authorized IP addresses or CIDR subnets from `ips.txt`, uses Nmap to scan TCP ports, attempts operating-system detection, preserves Nmap XML results, and creates a readable report in `result.txt`.

## Author

- **Author:** Mandy Chung
- **Version:** 1.0.0
- **Date:** October 17, 2026
- **Project:** Network Scanner
- **Language:** Python 3

## Purpose

This project demonstrates how Python can control Nmap, process structured XML output, identify open TCP ports, and report a probable operating system.

The program:

- Reads IP addresses or CIDR subnets from `ips.txt`.
- Validates each target before scanning.
- Removes duplicate targets.
- Scans TCP ports from 1 through 65,535.
- Identifies open TCP ports.
- Attempts remote operating-system detection.
- Displays Nmap progress in the terminal.
- Preserves the XML output for each scanned target.
- Parses the XML results using Python.
- Saves a formatted report to `result.txt`.

## Authorization Notice

Use this program only against systems and networks that you own or are explicitly authorized to test.

Do not scan public networks, school networks, workplace networks, or another person's devices without permission.

The author is not responsible for unauthorized use of this program.

## Requirements

The program requires:

- Python 3.
- Nmap.
- Permission to scan the selected targets.
- Administrator or root privileges for some Nmap scan features.
- A file named `ips.txt`.

## Installation

### Check Python

On Linux or macOS:

```bash
python3 --version
```

On Windows PowerShell:

```powershell
python --version
```

or:

```powershell
py --version
```

### Check Nmap

```bash
nmap --version
```

If Nmap is not installed, install it using the appropriate method for your operating system.

On Debian or Ubuntu Linux:

```bash
sudo apt update
sudo apt install nmap
```

On macOS with Homebrew:

```bash
brew install nmap
```

On Windows, download and install Nmap from the official Nmap website. Run PowerShell or Command Prompt as Administrator when using scan options that require elevated privileges.

## Project Files

The recommended repository structure is:

```text
network-scanner/
├── network_scanner.py
├── README.md
└── ips.example.txt
```

The local working directory may also contain:

```text
network-scanner/
├── network_scanner.py
├── README.md
├── ips.txt
├── ips.example.txt
├── result.txt
└── nmap_result_192.168.56.10.xml
```

The real `ips.txt`, scan reports, and XML results may contain private network information.

## Input File

The program reads targets from a fixed file named:

```text
ips.txt
```

The file must be in the same directory as `network_scanner.py`.

Example:

```text
# Authorized lab targets
192.168.56.10
192.168.56.20
```

A CIDR subnet can also be used:

```text
192.168.56.0/24
```

The input file supports:

- Individual IPv4 addresses, such as `192.168.56.10`.
- CIDR subnets, such as `192.168.56.0/24`.
- Blank lines.
- Comments beginning with `#`.

The program ignores blank lines and comments. Each remaining entry is validated using Python's `ipaddress` module.

## Example Input File

Create a local file named `ips.txt`:

```text
# Replace these with authorized lab targets
192.168.56.10
192.168.56.20
```

For a private lab subnet:

```text
192.168.56.0/24
```

Do not upload a real private target list to a public GitHub repository.

## Running the Program

Place these files in the same directory:

```text
network_scanner.py
ips.txt
```

### Linux or macOS

Run:

```bash
sudo python3 network_scanner.py
```

### Windows PowerShell

Run:

```powershell
python network_scanner.py
```

or:

```powershell
py network_scanner.py
```

Administrator or root privileges may be required because the program uses a TCP SYN scan and Nmap operating-system detection.

## Nmap Command

For each target, the program builds a command similar to:

```bash
nmap -sS -T4 --max-retries 0 -Pn -O --osscan-guess \
--max-os-tries 1 --stats-every 10s -p- \
-oX nmap_result_192.168.56.10.xml 192.168.56.10
```

The exact filename changes depending on the target.

## Nmap Options

| Option | Purpose |
|---|---|
| `-sS` | Performs a TCP SYN scan. |
| `-T4` | Uses a faster timing template. |
| `--max-retries 0` | Disables probe retransmissions to reduce scan time. |
| `-Pn` | Skips host discovery and scans the target directly. |
| `-O` | Attempts operating-system detection. |
| `--osscan-guess` | Allows close OS matches to be reported. |
| `--max-os-tries 1` | Limits OS detection to one attempt. |
| `--stats-every 10s` | Displays scan progress every 10 seconds. |
| `-p-` | Scans TCP ports 1 through 65,535. |
| `-oX filename` | Saves structured XML output to the specified file. |

## Option Details

### TCP SYN scan

The `-sS` option performs a TCP SYN scan. It sends SYN packets to TCP ports and analyzes the responses to determine whether ports are open, closed, or filtered.

This option may require Administrator privileges on Windows or root privileges on Linux and macOS.

### Timing template

The `-T4` option uses a faster Nmap timing profile. It can reduce scan time on a reliable local network, but it may generate more network traffic.

### Maximum retries

The `--max-retries 0` option disables retransmission attempts. This can make the scan faster, but packet loss may cause some ports or OS information to be missed.

### Skip host discovery

The `-Pn` option skips the normal host-discovery stage. Nmap treats the target as online and attempts the requested scan directly.

This can be useful when a firewall blocks ping or host-discovery probes. However, it can make a subnet scan slower because Nmap attempts to scan every specified address.

### Operating-system detection

The `-O` option enables Nmap operating-system detection. Nmap compares the target's network responses with known OS fingerprints.

The result is a probable OS estimate, not guaranteed proof of the operating system.

### OS guess

The `--osscan-guess` option allows Nmap to report close matches when it does not have enough information to make a highly confident identification.

### OS attempts

The `--max-os-tries 1` option limits Nmap to one operating-system detection attempt. This can reduce scan time but may reduce the chance of obtaining an OS match.

### Scan progress

The `--stats-every 10s` option displays progress information every 10 seconds while Nmap is running.

### All TCP ports

The `-p-` option scans TCP ports 1 through 65,535.

Scanning all ports can take considerably longer than scanning only common ports, especially when scanning a subnet.

### XML output

The `-oX` option saves Nmap's structured XML output to a file.

The XML files are preserved by this program because they may be useful for:

- Reviewing the complete Nmap output.
- Performing later analysis.
- Importing results into another tool.
- Validating the formatted text report.
- Demonstrating structured security-tool output.

## Program Workflow

The program follows these steps:

1. Check whether `ips.txt` exists.
2. Read the contents of the input file.
3. Split the file into separate lines.
4. Ignore blank lines and comments.
5. Validate every IP address or CIDR subnet.
6. Report invalid entries with their line numbers.
7. Remove duplicate targets.
8. Check whether Nmap is installed.
9. Build the Nmap command for the current target.
10. Run Nmap.
11. Save the Nmap results as XML.
12. Read the XML file.
13. Preserve the XML file on disk.
14. Parse the XML using `ElementTree`.
15. Extract host status, open ports, and OS information.
16. Combine results from all targets.
17. Display the final report in the terminal.
18. Save the formatted report to `result.txt`.

## Python Modules

### `ipaddress`

```python
import ipaddress
```

The `ipaddress` module validates IPv4 addresses and CIDR subnets before they are passed to Nmap.

Example:

```python
ipaddress.ip_network(
    target,
    strict=False,
)
```

### `shutil`

```python
import shutil
```

The `shutil` module checks whether Nmap is available in the system path.

Example:

```python
shutil.which("nmap")
```

### `subprocess`

```python
import subprocess
```

The `subprocess` module starts Nmap as an external process.

The program checks the return code to determine whether Nmap completed successfully.

### `sys`

```python
import sys
```

The `sys` module is used to:

- Print errors to standard error.
- Exit the program with an error status.

### `xml.etree.ElementTree`

```python
import xml.etree.ElementTree as ET
```

The `ElementTree` module parses Nmap's XML output.

The program uses it to extract:

- Host addresses.
- Host status.
- Operating-system matches.
- OS match percentages.
- Port protocols.
- Port numbers.
- Port states.

### `pathlib`

```python
from pathlib import Path
```

The `Path` class provides platform-independent file handling.

The program uses it to:

- Locate `ips.txt`.
- Create XML filenames.
- Read XML results.
- Save `result.txt`.

## Function Descriptions

### `read_targets()`

The `read_targets()` function reads the input file and prepares the targets for scanning.

It:

1. Checks that `ips.txt` exists.
2. Reads the file as UTF-8.
3. Splits the file into lines.
4. Removes unnecessary whitespace.
5. Ignores blank lines and comments.
6. Validates each target.
7. Reports invalid entries.
8. Removes duplicate targets.
9. Returns the validated target list.

### `run_nmap(target, xml_file)`

The `run_nmap()` function runs Nmap against one target.

It:

1. Checks whether Nmap is installed.
2. Builds the Nmap command.
3. Displays the command in the terminal.
4. Runs Nmap.
5. Displays Nmap progress.
6. Checks Nmap's exit status.
7. Verifies that the XML file exists.
8. Reads the XML file.
9. Returns the XML text.

The XML file is not deleted, so it remains available after the scan.

### `get_attribute(element, name, default)`

The `get_attribute()` function safely retrieves an XML attribute.

If the XML element or attribute is missing, it returns a default value instead of causing the program to crash.

### `parse_results(xml_output)`

The `parse_results()` function parses XML output and extracts the relevant information.

For each host, it extracts:

- IP address.
- Host status.
- Probable OS name.
- OS accuracy.
- Open TCP ports.

The program ignores ports that are not reported as open.

### `format_results(results)`

The `format_results()` function converts the parsed results into a readable text report.

The report includes:

- Host address.
- Host status.
- Probable OS.
- OS match percentage.
- Open TCP ports.

### `main()`

The `main()` function coordinates the complete program.

It:

1. Reads the input targets.
2. Creates an empty results list.
3. Scans each target.
4. Parses the XML output.
5. Combines all results.
6. Creates the final report.
7. Displays the report.
8. Writes the report to `result.txt`.
9. Handles errors.

## Output Files

The program creates two main types of output.

### XML output

For every target, Nmap creates an XML file with a name similar to:

```text
nmap_result_192.168.56.10.xml
```

For a CIDR subnet, the slash is replaced with an underscore:

```text
nmap_result_192.168.56.0_24.xml
```

The XML files contain structured scan information, including:

- Target address.
- Host status.
- Port states.
- Open ports.
- Service information provided by Nmap.
- Operating-system matches.
- Scan metadata.

The XML output is preserved for later review and processing.

### Text report

The program also creates:

```text
result.txt
```

Example:

```text
NETWORK SCAN RESULTS

Host: 192.168.56.10
Status: up
OS estimate: Linux 5.X
OS match: 92%
Open ports:
  tcp/22
  tcp/80
```

The actual results depend on the target system, network conditions, firewall configuration, and Nmap fingerprint information.

## Example Output

```text
NETWORK SCAN RESULTS

Host: 192.168.56.10
Status: up
OS estimate: Linux 5.X
OS match: 92%
Open ports:
  tcp/22
  tcp/80

Host: 192.168.56.20
Status: up
OS estimate: Unknown
OS match: N/A
Open ports:
  tcp/443
```

If no open ports are found, the program reports:

```text
Open ports: none
```

If Nmap cannot identify the operating system, the program reports:

```text
OS estimate: Unknown
OS match: N/A
```

## OS Detection Limitations

The operating-system result is not guaranteed.

Nmap performs remote OS fingerprinting by analyzing how a target responds to network probes. It compares those responses with known fingerprints and reports a probable match.

The result may be affected by:

- Firewalls.
- Packet filtering.
- Network address translation.
- Virtual machines.
- Packet loss.
- Modified TCP/IP stacks.
- Insufficient open or closed ports.
- Disabled retries.
- Aggressive scan settings.
- Unusual network devices.

For this reason, the output uses the label:

```text
OS estimate
```

It should not be interpreted as:

```text
Verified operating system
```

## Performance Considerations

The current program uses a full TCP port scan:

```text
-p-
```

This scans 65,535 TCP ports for each target.

A `/24` subnet can contain up to 256 addresses. Scanning all TCP ports across a complete `/24` subnet may therefore take a long time.

The program also uses:

```text
-Pn
```

This disables host discovery and causes Nmap to scan every target directly.

The following options reduce scan time:

```text
-T4
--max-retries 0
--max-os-tries 1
```

However, faster settings may reduce reliability.

To perform a faster test, replace:

```python
# Scans every TCP port from 1 through 65535.
"-p-",
```

with:

```python
# Scans Nmap's 100 most common TCP ports.
"--top-ports",
"100",
```

You may also remove:

```python
# Skip host discovery to scan target directly.
"-Pn",
```

Removing `-Pn` allows Nmap to perform host discovery before the port scan. This can avoid scanning addresses that appear to be offline.

## Testing Procedure

Before testing, verify that:

- Python 3 is installed.
- Nmap is installed.
- `ips.txt` contains an authorized target.
- The terminal has the required privileges.
- The script and `ips.txt` are in the same folder.

Run the program:

```bash
sudo python3 network_scanner.py
```

On Windows PowerShell:

```powershell
python network_scanner.py
```

After the scan completes:

1. Confirm that Nmap displays progress.
2. Confirm that the terminal displays scan results.
3. Confirm that `result.txt` exists.
4. Confirm that one or more XML files exist.
5. Open `result.txt`.
6. Review the XML file using a text editor or browser.
7. Capture a screenshot of the completed test.

## GitHub Files

The recommended GitHub repository should contain:

```text
network-scanner/
├── network_scanner.py
├── README.md
└── ips.example.txt
```

Use `ips.example.txt` to show the input format without publishing real private targets.

Example:

```text
# Replace these examples with authorized lab targets
192.168.56.10
192.168.56.20
```

# Local target list
ips.txt

# Generated text report
result.txt

# Generated XML scan files
nmap_result_*.xml

## Known Limitations

The program has the following limitations:

- It supports IPv4 targets and CIDR subnets.
- It does not validate IPv6 targets.
- OS detection is not guaranteed to be accurate.
- Full-port scans can take a long time.
- `-Pn` can increase scan time for subnets.
- `--max-retries 0` can cause missed results when packets are lost.
- `--max-os-tries 1` can reduce OS-detection reliability.
- Firewalls may hide ports or alter scan responses.
- Nmap must be installed separately.
- Administrator or root privileges may be required.
- The program should only be used for authorized testing.

## Future Improvements

Possible future improvements include:

- Adding command-line arguments for optional scan settings.
- Supporting IPv6 addresses.
- Adding service and version detection.
- Creating an HTML report.
- Adding a progress bar.
- Adding logging.
- Validating the XML against the Nmap DTD.
- Adding automated tests.
- Allowing the user to select a scan profile.
- Adding a configuration file.

## Educational Use

This project was created for educational purposes to demonstrate:

- Python file handling.
- IP-address validation.
- Subprocess execution.
- Nmap integration.
- XML parsing.
- Error handling.
- Report generation.
- Basic network-security concepts.

Use it only on systems and networks for which you have explicit authorization.
