"""
Description:
 This script generates different reports based on a gateway log file.

Usage:
 python3 log_investigation.py log_path

Parameters:
 log_path = Path to the gateway log file
"""

import log_analysis_lib
import re
import os
import pandas as pd

# Retrieve the path of the log file from the command line.
# Since the code segment exists outside of any function, the variable log_path is considered a global variable.
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Calculate the amount of traffic associated with each port.
    port_traffic = tally_port_traffic()
    
    # Generate reports for ports that have 100 or more entries, as instructed in step 9.
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Create a report detailing invalid user login attempts.
    generate_invalid_user_report()

    # Produce a log containing records originating from IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """This function generates a dictionary where destination port numbers extracted from a designated log file are used as keys, and the values represent the frequency of occurrence of each port number.

    Returns:
        dict: Dictionary of destination port number counts
    """
    dpt_logs = log_analysis_lib.filter_log_by_regex(log_path, r'DPT=(\d+)')[1]
    dpt_tally = {}

    for dpt in dpt_logs:
        dpt_tally[dpt[0]] = dpt_tally.get(dpt[0], 0) + 1

    return dpt_tally

def generate_port_traffic_report(port_number):
    """Creates a CSV report containing all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    capture_data = []

    with open(log_path, 'r') as file:
        for record in file:
            pattern = f'DPT={port_number}'
            search_flags = re.IGNORECASE
            match = re.search(pattern, record, search_flags)
            if match:
                match1 = re.search(r'([A-Za-z]+\s+[0-9]+\s+[0-9:]+).*SRC=(\S+)\s+DST=(\S+).*SPT=(\d+)\s+DPT=(\d+)', record, search_flags)
                if match1:
                    capture_data.append(match1.groups())

    df = pd.DataFrame(capture_data, columns=['Date', 'Source IP address', 'Destination IP address', 'Source port', 'Destination port'])
    file_name = f'destination_port_{port_number}_report.csv'
    df.to_csv(file_name, index=False)
    print(f"Report for destination port {port_number} saved as {file_name}")

def generate_invalid_user_report():
    """Generates a CSV report of all network activities in a log file indicating an attempt to log in as an invalid user.
    """
    capture_data = []

    with open(log_path, 'r') as file:
        for record in file:
            pattern = 'Invalid user'
            search_flags = re.IGNORECASE
            match = re.search(pattern, record, search_flags)
            if match:
                match1 = re.search(r'([A-Za-z]+\s+[0-9]+\s+[0-9:]+).*Invalid user (\S+) from (\S+)', record, search_flags)
                if match1:
                    capture_data.append(match1.groups())

    df = pd.DataFrame(capture_data, columns=['Date', 'Time', 'Username', 'IP Address'])
    file_name = 'invalid_users.csv'
    df.to_csv(file_name, index=False)
    print(f"Invalid users report saved as {file_name}")

def generate_source_ip_log(ip_address):
    """Generates a plain text .log file containing all records from a source log
    file that match a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    all_info_src_address = log_analysis_lib.filter_log_by_regex(log_path, rf'.*SRC={ip_address}.*')[0]
    file_name = f'source_ip_{ip_address.replace(".", "_")}.log'
    
    with open(file_name, 'w') as file:
        for record in all_info_src_address:
            file.write(record + '\n')
    
    print(f"Log for source IP {ip_address} saved as {file_name}")

if __name__ == '__main__':
    main()
