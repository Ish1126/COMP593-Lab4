"""
Description:
 This script generates different reports based on a gateway log file.

Usage:
 python3 log_investigation.py log_investigation

Parameters:
 log_path = Path to the gateway log file
"""
import log_analysis_lib
import re
import os
import pandas as pd

# Retrieve the path of the log file from the command line.
# Since the code segment exists outside of any function, the cariable log_path is considered a global variable.
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

    #   Produce a log containing records originating from IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """This function generates a dictionary where destination port numbers extracted from a designed log file are used as keys, and the values represent the frequency of occurrence of each port number.

    Returns:
        dict: Dictionary of destination port number counts
    """
    # TODO: Finish implementatig the function body as described in step 7.
    dpt_logs = log_analysis_lib.filter_log_by_regex(log_path, r'DPT=(.*?) ')[1]

    dpt_tally = {}

    for dpt in dpt_logs:
        dpt_tally[dpt[0]] = dpt_tally.get(dpt[0], 0) + 1

    return dpt_tally

def generate_port_traffic_report(port_number):
    """Creates a CSV report conating all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    # TODO: Finish implementing the function body according to step 8
    # Retrieve information from records that include the designated destination port
    capture_data = []
    
    with open(log_path,'r') as file:
        
        for record in file:
            pattern = f'.*DPT={port_number}.*'
            search_flags= re.IGNORECASE
            match = re.search(pattern,record,search_flags)
            if match:
                match1 = re.search(r'([A-Za-z].*[0-9][0-9]) ([0-9][0-9].[0-9][0-9].[0-9][0-9]).*SRC=(.*?) DST=(.*?) .*SPT=(.*?) DPT=(.*?) ',record, search_flags)
                capture_data.append(match1.groups())
                file_path = os.path.dirname(os.path.abspath('log_investigation.py'))
                file_name = f'destination_port_{port_number}_report.csv'
                proper_file_path = os.path.join(file_path,file_name)
                df = pd.DataFrame(capture_data,columns=('Date','time','Source IP address','Destination IP address','Source port','Destination port'))
                df.to_csv(proper_file_path, index=False)
    # Generate the CSV report

    return

def generate_invalid_user_report():
    """Generates a CSV report of all network activities in a log file indicating an attempt to log in as an invalid user.
    """
    # TODO: Finalize function implementation as per instructions in step 10
    # Retrieve information from records indicating attempted invalid user login.
    # Create the CSV report from the retrieved data.
    capture_data = []
    with open(log_path,'r') as file:
        for record in file:
            
            pattern = '.*Invalid user.*'
            search_flags = re.IGNORECASE
            match = re.search(pattern,record,search_flags)
            if match:
                match1 = re.search(r'([A-Za-z].*[0-9][0-9]) ([0-9][0-9].[0-9][0-9].[0-9][0-9]).*Invalid user ([A-Za-z]*) .* ([0-9]+.[0-9]+.[0-9]+.[0-9]+)',record)
                capture_data.append(match1.groups())
                file_path = os.path.dirname(os.path.abspath('log_investigation.py'))
                file_name = 'invalid_users.csv'
                proper_file_path = os.path.join(file_path,file_name)
                df = pd.DataFrame(capture_data,columns=('Date','time','Username','IP Adrress'))
                df.to_csv(proper_file_path, index=False)
    return

def generate_source_ip_log(ip_address):
    """Generates a plain text .log file containing all records from a source log
    file that match a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # TODO: Implement the function body as instructed in step 11
    # Retrieve all records that match the provided source IP address
    # Store all matching records in a .log file in plain text format
    all_info_src_address = log_analysis_lib.filter_log_by_regex(log_path, r'.*SRC=220.195.35.40.*')[0]
    #print(all_info_src_address)
    file_path = os.path.dirname(os.path.abspath('log_investigation.py'))
    new = re.sub(r'\.' , '_' , ip_address)
    file_name = f'source_ip_{new}.txt'
    proper_file_path = os.path.join(file_path,file_name)
    o_file = open(proper_file_path,"a")
    for record1 in all_info_src_address:
        o_file.write(record1)
        o_file.write('\n')
    o_file.close()    
    return

if __name__ == '__main__':
    main()