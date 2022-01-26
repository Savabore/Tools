# CarbonBlack Def Export Tool
This tool uses the Carbon Black API to export events based on criteria given at run time.

## Dependencies
| Library Name | Install Method |
| --- | --- |
| cbapi | pip install cbapi |

## Setup CBAPI
1. Install cbapi:
```
python3 -m pip install cbapi
```
2. Configure cbapi: 
```
cbapi-defense configure
```
3. Follow the prompts: You will need to enter the *URL* for the Server, *Connector ID*, and *API Key*

## Executing the script
The script is ran from the command line as follow:

```
python3 cred-tool.py
```

To get to the help menu use:

```
cb_def_export.py -h
```
[[Images/CBd_1.png]]

## Search Requirements
In order to perform a search criteria must be provided.

Criteria is a hostname, sha256 hash value, application name, or Event Type.

A search window must also be provided.

Available windows: (3h, 1d, 1w, 2w)
*Goes backwards from current date and time.*

Start date and end date: 2019-01-01 2019-01-15

*No window can exceed a two week time period*

Example:
```
python3 cb_def_export.py -t NETWORK -W 1h
```

The exporter only supports one criteria at a time.

## Export
The script will export the search as a csv file in the current working directory where the script was ran.
