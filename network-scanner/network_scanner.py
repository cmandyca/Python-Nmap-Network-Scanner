"""
Network Scanner

Author: Mandy Chung
Version: 1.0.0
Date: 2026-10-17

Purpose:
    Read IP addresses or subnets from ips.txt.
    Use Nmap to scan all TCP ports.
    Identify open ports.
    Attempt operating-system detection.
    Display scan progress in the terminal.
    Create Nmap XML output.
    Save formatted results to result.txt.

Limitations:
    Nmap OS detection is a fingerprint-based estimate, not guaranteed.
"""

# Imports the module used to validate IP addresses and subnets.
import ipaddress

# Imports the module used to check whether Nmap is installed.
import shutil

# Imports the module used to run Nmap as an external process.
import subprocess

# Imports the module used to display errors and exit the program.
import sys

# Imports Python's XML parser for reading Nmap output.
import xml.etree.ElementTree as ET

# Imports Path for reading and writing files.
from pathlib import Path


# Stores the name of the file containing IP addresses and subnets.
INPUT_FILE = Path("ips.txt")

# Stores the name of the final formatted report.
OUTPUT_FILE = Path("result.txt")


def read_targets():
    """Read and validate IP addresses or subnets from ips.txt."""

    # Creates an empty list for valid targets.
    targets = []

    # Checks whether the input file exists.
    if not INPUT_FILE.exists():

        # Stops the program if ips.txt is missing.
        raise FileNotFoundError(
            "ips.txt was not found in the current directory."
        )

    # Reads the contents of ips.txt as UTF-8 text.
    file_contents = INPUT_FILE.read_text(
        encoding="utf-8"
    )

    # Splits the file into separate lines.
    lines = file_contents.splitlines()

    # Processes each line and records its line number.
    for line_number, line in enumerate(lines, start=1):

        # Removes leading and trailing whitespace.
        target = line.strip()

        # Skips blank lines and lines beginning with #.
        if not target or target.startswith("#"):

            # Moves to the next line.
            continue

        # Starts error handling for target validation.
        try:

            # Validates an IPv4 address or CIDR subnet.
            ipaddress.ip_network(
                target,
                strict=False,
            )

            # Adds the valid target to the target list.
            targets.append(target)

        # Handles invalid IP addresses or subnets.
        except ValueError as error:

            # Reports the invalid target and its line number.
            raise ValueError(
                f"Invalid target on line {line_number}: {target}"
            ) from error

    # Checks whether the file contained any valid targets.
    if not targets:

        # Stops the program when no valid targets exist.
        raise ValueError(
            "ips.txt does not contain a valid target."
        )

    # Removes duplicate targets while preserving their order.
    unique_targets = list(dict.fromkeys(targets))

    # Returns the validated target list.
    return unique_targets


def run_nmap(target, xml_file):
    """Run Nmap against one target and return its XML output."""

    # Checks whether the nmap executable is available.
    if shutil.which("nmap") is None:

        # Stops the scan if Nmap is not installed.
        raise RuntimeError(
            "Nmap was not found. Install it before running the script."
        )

    # Creates the command list that will be passed to Nmap.
    command = [

        # Calls the Nmap program.
        "nmap",

        # Performs a TCP SYN scan.
        "-sS",

        # Uses Nmap's faster timing template.
        "-T4",
        
        # Limit retransmissions to speed up the scan.
        "--max-retries",
        "0",
        
        # Skip host discovery to scan target directly.
        "-Pn",

        # Enables operating-system detection.
        "-O",

        # Allows Nmap to report close OS matches.
        "--osscan-guess",

        # Performs only one OS-detection attempt.
        "--max-os-tries",
        "1",

        # Displays timing progress every 10 seconds.
        "--stats-every",
        "10s",

        # Scans every TCP port from 1 through 65535.
        "-p-",

        # Writes structured XML output to the specified file.
        "-oX",
        str(xml_file),

        # Adds the IP address or subnet to scan.
        target,
    ]

    # Displays the target currently being scanned.
    print(f"\nScanning target: {target}")

    # Displays the Nmap command for troubleshooting and documentation.
    print("Nmap command:")

    # Joins the command list into one readable command line.
    print(" ".join(command))

    # Prints a blank line before scan progress begins.
    print()

    # Runs Nmap command.
    completed = subprocess.run(
        command
    )

    # Checks whether Nmap returned a nonzero exit status.
    if completed.returncode != 0:

        # Stops processing this target and reports the Nmap error.
        raise RuntimeError(
            f"Nmap exited with status {completed.returncode}."
        )

    # Checks whether Nmap created the XML file.
    if not xml_file.exists():

        # Reports the missing output file.
        raise RuntimeError(
            f"Nmap did not create {xml_file}."
        )

    # Reads the XML file as UTF-8 text.
    xml_output = xml_file.read_text(
        encoding="utf-8"
    )

    # Returns the XML text to the calling function.
    return xml_output


def get_attribute(element, name, default="unknown"):
    """Return an XML attribute or a default value."""

    # Checks whether the requested XML element is missing.
    if element is None:

        # Returns the default value when the element is missing.
        return default

    # Returns the requested XML attribute.
    return element.get(
        name,
        default,
    )


def parse_results(xml_output):
    """Extract host status, open ports, and OS estimates."""

    # Converts the XML text into an XML element tree.
    root = ET.fromstring(xml_output)

    # Creates a list for the parsed host results.
    results = []

    # Finds every host element in the XML document.
    for host in root.findall("host"):

        # Finds the address element for the current host.
        address_element = host.find("address")

        # Checks whether the address element is missing.
        if address_element is None:

            # Skips an incomplete host record.
            continue

        # Extracts the IP address from the XML element.
        address = get_attribute(
            address_element,
            "addr",
        )

        # Finds the host-status element.
        status_element = host.find("status")

        # Extracts the host status, such as up or down.
        status = get_attribute(
            status_element,
            "state",
        )

        # Finds Nmap's highest-ranked OS match.
        os_match = host.find("./os/osmatch")

        # Checks whether Nmap found an OS match.
        if os_match is None:

            # Uses Unknown when no OS match is available.
            os_name = "Unknown"

            # Uses N/A when no accuracy value is available.
            os_accuracy = "N/A"

        else:

            # Extracts Nmap's probable OS name.
            os_name = get_attribute(
                os_match,
                "name",
            )

            # Extracts Nmap's reported match percentage.
            os_accuracy = get_attribute(
                os_match,
                "accuracy",
            )

        # Creates a list for open ports on the current host.
        open_ports = []

        # Finds every scanned port for the current host.
        for port_element in host.findall("./ports/port"):

            # Finds the state element for the current port.
            state_element = port_element.find("state")

            # Checks whether the port state is missing.
            if state_element is None:

                # Skips an incomplete port record.
                continue

            # Reads the port state.
            port_state = state_element.get(
                "state"
            )

            # Ignores ports that are not open.
            if port_state != "open":

                # Moves to the next port.
                continue

            # Extracts the transport protocol.
            protocol = get_attribute(
                port_element,
                "protocol",
            )

            # Extracts the port number.
            port_number = get_attribute(
                port_element,
                "portid",
            )

            # Creates a readable protocol/port value.
            port_name = f"{protocol}/{port_number}"

            # Adds the open port to the list.
            open_ports.append(port_name)

        # Creates a dictionary containing this host's results.
        host_result = {
            "address": address,
            "status": status,
            "os": os_name,
            "accuracy": os_accuracy,
            "open_ports": open_ports,
        }

        # Adds the host result to the complete results list.
        results.append(host_result)

    # Returns all parsed host results.
    return results


def format_results(results):
    """Create a readable text report."""

    # Creates the first lines of the report.
    lines = [
        "NETWORK SCAN RESULTS",
        "",
    ]

    # Processes each host result.
    for result in results:

        # Adds the host IP address to the report.
        lines.append(
            f"Host: {result['address']}"
        )

        # Adds the host status to the report.
        lines.append(
            f"Status: {result['status']}"
        )

        # Adds the probable operating system.
        lines.append(
            f"OS estimate: {result['os']}"
        )

        # Adds Nmap's OS match percentage.
        lines.append(
            f"OS match: {result['accuracy']}%"
        )

        # Checks whether open ports were found.
        if result["open_ports"]:

            # Adds an open-port heading.
            lines.append("Open ports:")

            # Adds every open port to the report.
            for port in result["open_ports"]:

                # Adds one port per report line.
                lines.append(
                    f"  {port}"
                )

        else:

            # Reports that no scanned ports were open.
            lines.append(
                "Open ports: none"
            )

        # Adds a blank line between hosts.
        lines.append("")

    # Joins all report lines into one string.
    report = "\n".join(lines)

    # Returns the completed report.
    return report


def main():
    """Read ips.txt, scan targets, and create result.txt."""

    # Starts the main error-handling block.
    try:

        # Reads and validates targets from ips.txt.
        targets = read_targets()

        # Creates a list for all successful scan results.
        all_results = []

        # Processes one target at a time.      
        for target in targets:
            
            # Set a filename for the temporary XML file
            target_xml_filename = target
            
            # Check if the the target is in CIDR format with "/"
            if "/" in target:
                
                # Replace the special character "/" with "_" to avoid path error in later script.
                target_xml_filename = target.replace("/", "_")
            
            # Creates a unique temporary XML filename.
            xml_file = Path(
                f"nmap_result_{target_xml_filename}.xml"
            )    

            # Starts error handling for the current target.
            try:

                # Runs Nmap against the current target.
                xml_output = run_nmap(
                    target,
                    xml_file,
                )

                # Parses Nmap's XML output.
                results = parse_results(
                    xml_output
                )

                # Adds the current results to the complete list.
                all_results.extend(results)

            # Handles errors for the current target.
            except (
                OSError,
                RuntimeError,
                ET.ParseError,
            ) as error:

                # Reports the failure and continues to the next target.
                print(
                    f"Scan failed for {target}: {error}",
                    file=sys.stderr,
                )

        # Checks whether at least one host result was collected.
        if not all_results:

            # Stops if every scan failed or found no results.
            raise RuntimeError(
                "No scan results were successfully collected."
            )

        # Converts all results into a readable text report.
        report = format_results(
            all_results
        )

        # Displays the final report in the terminal.
        print("\n" + report)

        # Saves the final report with utf-8 encoding to result.txt.
        OUTPUT_FILE.write_text(
            report,
            encoding="utf-8",
        )

        # Confirms that the report was saved.
        print(
            f"Results saved to {OUTPUT_FILE}"
        )

    # Handles errors that stop the overall program.
    except (
        FileNotFoundError,
        OSError,
        RuntimeError,
        ValueError,
        ET.ParseError,
    ) as error:

        # Displays the error message.
        print(
            f"Error: {error}",
            file=sys.stderr,
        )

        # Exits with a failure status.
        sys.exit(1)


# Checks whether this file is being run directly.
if __name__ == "__main__":

    # Calls the main function.
    main()
