"""
Library of functions that are useful for analyzing plain-text log files.
"""
import re
import sys
import os
import pandas as pd

def main():
    # Retrieve the file path of the log file from the command line.
    log_path = get_file_path_from_cmd_line()

    # TODO: Implement the usage of filter_log_by_regex() to examine the gateway log as outlined in Step 5
    filter_log_by_regex(log_path, 'error', print_records=True, print_summary=True )
    
    # TODO: Implement the usage of filter_log_by_regex() to extract information from the gateway log according to Step 6
    
    filtered_records, extracted_data = filter_log_by_regex(log_path, 'SRC=(.*?) DST=(.*?) LEN=(.*?) ')
    extracted_df = pd.DataFrame(extracted_data, columns = ('Source ip', 'Destination IP', 'Length'))
    extracted_df.to_csv('data.csv', index = False)
    return


def get_file_path_from_cmd_line(param_num=1):
    """Obtains the file path from a command line parameter.

    Terminates the script if no file is provided as a command line parameter or if the specified path does not correspond to an existing file.

    Parameters:
        param_num (int): The posstion of the command line parameter containing the file path. Default is 1.

    Returns:
        str: The file path
    """
    # TODO: Complete the function implementation as described in Step 3.
    if len(sys.argv) < param_num+1:
        print(f'Error: Mising log file path expected as command line parameter {param_num}.')
        sys.exit(1)

    log_path = os.path.abspath(sys.argv[param_num])

    if not os.path.isfile(log_path):
        print(f'Error: {log_path} is not a valid filepath.')
        sys.exit(2)
        
    return log_path


def filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=False, print_records=False):
    """Retrieves a collection of records from a log file that satisfy a specified regex pattern.

    Parameters:
        log_file (str): Path of the log file
        regex (str): The regular expression filter
        ignore_case (bool, optional): Indicates whether to perform case-insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Determines if a summary of the results should be printed. Defaults to False.
        print_records (bool, optional): Determines if all records matching the regex should be printed. Defaults to False.

    Returns:
        (list, list): A list of records matching the regex pattern, and a list of tuples containing captured data.
    """
    # Initalize lists that will be returned by the function
    filtered_records = []
    captured_data = []

    # Set the flag for case sensitivity in the regex search.
    search_flags = re.IGNORECASE if ignore_case else 0

    # Go through the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Examine each line for a regular expression match.
            match = re.search(regex, record, search_flags)
            if match:
                # Append lines that meet the regular expresion criteruia to the list of filtered records.
                filtered_records.append(record[:-1]) # Eliminate the ending newline character.
                # Verify whether the regex match includes any captured groups.
                if match.lastindex:
                    # Append the tuple of captured data to the list of captured data.
                    captured_data.append(match.groups())

    # Print all the records if the option to print is enabled.
    if print_records is True:
        print(*filtered_records, sep='\n', end='\n')

    # Print a summary of the results if the option to print is enabled.
    if print_summary is True:
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')

    return (filtered_records, captured_data)

if __name__ == '__main__':
    main()              