import log_analysis_lib
import re
import os
import pandas as pd
import sys

def get_file_path_from_cmd_line():
    if len(sys.argv) != 2:
        print("Usage: python log_analysis_lib.py <log_file_path>")
        sys.exit(1)
    return sys.argv[1]

def main():
    # Retrieve the path of the log file from the command line.
    log_path = log_analysis_lib.get_file_path_from_cmd_line()

    # Calculate the amount of traffic associated with each port.
    port_traffic = tally_port_traffic(log_path)
    
    # Generate reports for ports that have 100 or more entries, as instructed in step 9.
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(log_path, port)

    # Create a report detailing invalid user login attempts.
    generate_invalid_user_report(log_path)

    # Produce a log containing records originating from IP 220.195.35.40
    generate_source_ip_log(log_path, '220.195.35.40')

def tally_port_traffic(log_path):
    """This function generates a dictionary where destination port numbers extracted from a designed log file are used as keys, and the values represent the frequency of occurrence of each port number.

    Args:
        log_path (str): Path to the log file.

    Returns:
        dict: Dictionary of destination port number counts
    """
    dpt_logs = log_analysis_lib.filter_log_by_regex(log_path, r'DPT=(.*?) ')[1]

    dpt_tally = {}

    for dpt in dpt_logs:
        dpt_tally[dpt[0]] = dpt_tally.get(dpt[0], 0) + 1

    return dpt_tally

def generate_port_traffic_report(log_path, port_number):
    """Creates a CSV report containing all network traffic in a log file for a specified destination port number.

    Args:
        log_path (str): Path to the log file.
        port_number (str or int): Destination port number
    """
    capture_data = []
    
    with open(log_path, 'r') as file:
        for record in file:
            pattern = f'.*DPT={port_number}.*'
            search_flags = re.IGNORECASE
            match = re.search(pattern, record, search_flags)
            if match:
                match1 = re.search(r'([A-Za-z].*[0-9][0-9]) ([0-9][0-9].[0-9][0-9].[0-9][0-9]).*SRC=(.*?) DST=(.*?) .*SPT=(.*?) DPT=(.*?) ', record, search_flags)
                capture_data.append(match1.groups())
                
                file_path = os.path.dirname(os.path.abspath(__file__))
                file_name = f'destination_port_{port_number}_report.csv'
                proper_file_path = os.path.join(file_path, file_name)
                
                df = pd.DataFrame(capture_data, columns=('Date', 'Time', 'Source IP address', 'Destination IP address', 'Source port', 'Destination port'))
                df.to_csv(proper_file_path, index=False)

def generate_invalid_user_report(log_path):
    """Generates a CSV report of all network activities in a log file indicating an attempt to log in as an invalid user.

    Args:
        log_path (str): Path to the log file.
    """
    capture_data = []
    
    with open(log_path, 'r') as file:
        for record in file:
            pattern = '.*Invalid user.*'
            search_flags = re.IGNORECASE
            match = re.search(pattern, record, search_flags)
            if match:
                match1 = re.search(r'([A-Za-z].*[0-9][0-9]) ([0-9][0-9].[0-9][0-9].[0-9][0-9]).*Invalid user ([A-Za-z]*) .* ([0-9]+.[0-9]+.[0-9]+.[0-9]+)', record)
                capture_data.append(match1.groups())
                
                file_path = os.path.dirname(os.path.abspath(__file__))
                file_name = 'invalid_users.csv'
                proper_file_path = os.path.join(file_path, file_name)
                
                df = pd.DataFrame(capture_data, columns=('Date', 'Time', 'Username', 'IP Address'))
                df.to_csv(proper_file_path, index=False)

def generate_source_ip_log(log_path, ip_address):
    """Generates a plain text .log file containing all records from a source log file that match a specified source IP address.

    Args:
        log_path (str): Path to the log file.
        ip_address (str): Source IP address
    """
    all_info_src_address = log_analysis_lib.filter_log_by_regex(log_path, f'.*SRC={ip_address}.*')[0]
    
    file_path = os.path.dirname(os.path.abspath(__file__))
    new_ip = re.sub(r'\.', '_', ip_address)
    file_name = f'source_ip_{new_ip}.log'
    proper_file_path = os.path.join(file_path, file_name)
    
    with open(proper_file_path, 'w') as o_file:
        for record in all_info_src_address:
            o_file.write(record + '\n')

if __name__ == '__main__':
    main()
