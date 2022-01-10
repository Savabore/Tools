# Leak Checker

This tool is a command line tool that allows the user to query a list of emails and passwords in IBM BluePages and *Have I Been PWND*. The results will be in a *CSV* file containing the status of the email and if it is associated with any online credential leaks.

### Download the script [here](...s/blob/master/cred-tool.py)

## Dependencies
| Library Name | Install Method |
| --- | --- |
| python-ldap | pip install python-ldap |
| urllib3 | pip install urllib3 |
| certifi | pip install certifi |

Depending on your **OS** there may be other dependencies required for the the python-ldap to install; refer to the [Documentation](https://www.python-ldap.org/en/python-ldap-3.2.0/) if you run into any issues.

## Executing the script
The script is ran from the command line as follows *python3 cred-tool.py*. The input file must be a flat *text*  or *csv* file created using a text editor. Any issues with the script may be due to hidden formatting characters like spaces, return carriages, or extra new lines.

__**If only searching single criteria then use a text file with each email on a new line.**__

example.txt
```
john.doe@example.com
jane.doe@somemail.com
```

__**If searching multiple criteria ie **emails and passwords** then a *csv* file must be used.**__

example.csv
```
john.doe@example.com, password01
jane.doe@somemail.com, supas3cr3pass0rd
```

## Help Menu
```
>python3 cred-tool.py -h
usage: Check credentials against the Have I Been PWND API

optional arguments:
  -h, --help            show this help message and exit
  -s, --single          Search Have I Been PWND for single criteria. ie. Just
                        Emails or Just Passwords
  -m, --multiple        Search Have I Been PWND for multiple criteria. ie.
                        Emails and Passwords
  -IF INPUT, --input_file INPUT
                        File containing criteria to search for. Example:
                        criteria.txt For single item; ie "emails" then each
                        line must contain a single email. For both; each line
                        must contain BOTH the email and password separated by
                        a comma.
  -OP OUTPUT, --output_path OUTPUT
                        Path to save results file.
```

### Single Criteria Usage
*python3 cred-tool.py -s -IF examplefile*

### Multiple Criteria Usage
*python3 cred-tool.py -m -IF examplefile.csv*

### Output Path
By default the tool will always create the output file as a *csv* in the local directory in which the tool was run. This can be changed to any path of the users choice by using the ***-Op*** argument.

### Output File
The file will always be a *csv* formatted file. The file will always have the same name as the input file but will have *.csv* appended to the end of it. 

__**Input File**__
```
example.csv
```
__**Output File**__
```
example.csv.csv
```
__**Input File**__
```
example
```
__**Output File**__
```
example.csv
```
## Results
The Results will always be output as a *csv* similar to the example below.

| Email | AccountStatus	| AccountType | Last Password Change | Password | Times Password Leaked | Times Email Leaked | Domains | Dates | Most Recent | Data Types Leaked |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| john.doe@example.com | Not-Found | N/A | | N/A | N/A | N/A | N/A | N/A | N/A |
| jane.doe@somemail.com | Not-Found | N/A | | N/A | N/A | N/A | N/A | N/A | N/A |
