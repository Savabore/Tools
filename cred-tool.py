# cred-tool.py
# This script is intended to assist in analysis of leaked credentials
# The script queries LDAP to determine if an email is associated to an active LDAP account
#If an active account is found, it reports the type of account (I.E. employee, contractor, vendor, etc)
# Additionally, active accounts are also queried in the hibp database for additional context to possibly
#determine the source of the leak, date of the leak, types of data etc. so an analyst can decide whether
#or not a user notification is necessary.
#
#Author: 
#
#CHANGE HISTORY
#v1 published 3/19/2019
#v2 published 9/17/2019
#### support for HIBP APIV3
#v3 published 9/20/2019
#v4 published 4/28/2021


import json
import os

# BluePages class is the function for querying LDAP checking the records employeeType,
#passwordModifyTimestamp, and the DN to see if the record has been deleted.
class BluePages:

    def __init__(self, _email):
        import ldap
        self.result = {'AccountStatus': '','AccountType': '','PasswordTimeStamp': ''}
        self.ldap = ldap.initialize('ldap://www.site.com:389')
        # query LDAP by email account on o=ibm.com
        s = self.ldap.search_s('ou=bluepages,o=ibm.com', ldap.SCOPE_SUBTREE, '(mail=' + _email + ')', ['ou=bluepages','hrActive','employeeType','passwordModifyTimestamp'])
        if s:
            for o in s:
                r = o[1]
                md = str(r['passwordModifyTimestamp'])
                try:
                    etype = str(r['employeeType'])
                    if etype.strip("[b']") == 'P': # the strip function is to remove a leading b' that was included in the results for some reason
                        self.result.update({'AccountType': 'Employee'})
                    if etype.strip("[b']") == 'C':
                        self.result.update({'AccountType': 'Contractor'})
                    if etype.strip("[b']") == 'X':
                        self.result.update({'AccountType': 'Temporary'})
                    if etype.strip("[b']") == 'V':
                        self.result.update({'AccountType': 'Vendor'})
                    if etype.strip("[b']") == 'Q':
                        self.result.update({'AccountType': 'FunctionalID'})
                    if etype.strip("[b']") == 'L':
                        self.result.update({'AccountType': 'LeaveOfAbsence'})
                except KeyError:
                    self.result.update({'AccountType': 'Unknown'})
                try:
                    hrstatus = str(r['hrActive'])
                    if hrstatus.strip("[b']") == 'A': # the strip function is to remove a leading b' that was included in the results for some reason
                        self.result.update({'AccountStatus': 'Active'})
                    if hrstatus.strip("[b']") == 'I': # the strip function is to remove a leading b' that was included in the results for some reason
                        self.result.update({'AccountStatus': 'Inactive'})
                except KeyError:
                    self.result.update({'AccountStatus': 'Unknown'})
                self.result.update({'PasswordTimeStamp': md.strip("[b']")}) # update the password changed timestamp
        if not s: # if not found in o=site.com, now query o=deleted.site.com
            s = self.ldap.search_s('ou=bluepages,o=deleted.site.com', ldap.SCOPE_SUBTREE, '(mail=' + _email + ')', ['ou=bluepages','hrActive','employeeType','passwordModifyTimestamp'])
            if s: self.result.update({'AccountStatus': 'Deleted'})
        if not s: # if still not found then this email is not valid and "Not Found" in LDAP
            self.result.update({'AccountStatus': 'Not Found','AccountType': 'Not Found','PasswordTimeStamp': 'N/A'})

    def __setitem__(self, key, status):
        self.result[key] = status

    def __getitem__(self, status):
        return self.result[status]


class HibpApi:
    #Constructs the Have I Been Pwned API Query.
    #Requires an API key, user agent, and a query parameter to pull all the results back.
    #Input includes both emails and passwords.
    import urllib3
    import certifi

	# pool manager handles all of the details of connection pooling and thread safety
    http = urllib3.PoolManager(
        ca_certs=certifi.where(),
        cert_reqs='CERT_REQUIRED' #require HTTPS protocol
    )

    @staticmethod
    def email(_criteria):
        #API get request for email accounts defined here, the response returned in `r`
        h = HibpApi.http
        r = h.request("GET", 'https://haveibeenpwned.com/api/v3/breachedaccount/' + str(_criteria),
                      headers={
                      'hibp-api-key':'<api>', #API key
                      'user-agent':'IBM-Threat' #requires a user agent
                      },
                      fields={
                      'truncateResponse':'false' #without this parameter only basic info is returned
                      }
                      )
                      #error code handling below
        if r.status == 404:
            return 'Not Found'
        if r.status == 200:
            return json.loads(r.data.decode('utf-8'))
        if r.status == 400:
            raise ValueError("Bad request: "
                             "\n The account does not comply with an acceptable format (i.e. it's an empty string)")
        if r.status == 403:
            raise ValueError('Forbidden: \n'
                             'No user agent has been specified in the request')
        if r.status == 429:
            raise ValueError('Too many requests: \n'
                             'The rate limit has been exceeded')
        else:
            raise ValueError('API returned a status code of: ' + str(r.status) + '\n' + str(r.data.decode()))

    @staticmethod
    def password(_criteria):
    #API get request for passwords defined here, the response returned in `r`
        h = HibpApi.http
        r = h.request('GET', 'https://api.pwnedpasswords.com/range/' + str(_criteria))

        if r.status == 200:
            raw = str(r.data.decode()).lower()
            return raw
        else:
            raise ValueError('API returned a status code of: ' + str(r.status) + '\n' + str(r.data.decode()))


class InputFile:
    # Parses input file into two lists based on input at runtime
    # Will create a list of emails and passwords for later search with the API
    def __init__(self, _file):
        self.file = _file
        self.result = {}

    def parse_file(self):
        import hashlib
        import re
        email = re.compile("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+$)")
        hashes = re.compile("(^[0-9a-fA-F]{32,40}$)")

        try:
            with open(self.file, 'r') as f:
                index = 0
                for line in f:
                    sha_1 = hashlib.sha1()
                    sn = line.rstrip('\n')
                    sc = sn.split(',')
                    self.result[index] = {'email': '', 'password': '', 'hash': ''}
                    for i in sc:
                        p = i.strip()
                        if email.match(p):
                            self.result[index].update({'email': p})
                        if not email.match(p) or hashes.match(p):
                            sha_1.update(p.encode('utf-8'))
                            self.result[index].update({'password': p})
                            self.result[index].update({'hash': sha_1.hexdigest()})
                        if hashes.match(p):
                            self.result[index].update({'password': '(' + p + ') Possible Hash'})
                            self.result[index].update({'hash': ''})
                    index += 1
            return self.result
        except FileNotFoundError:
            print('Unable to find file for input.')


class Query:
    # Takes input file and output file arguments.
    # Passes input file to the file parser, queries the API and generates output file
    def __init__(self, _input, _output):
        self.qe = HibpApi.email
        self.qp = HibpApi.password
        self.i_f = InputFile(_input)
        self.o_f = _output
        # Create the column headers of the csv output file
        self.qv = {'Email': '', 'AccountStatus': '', 'AccountType': '', 'Last Password Change': '', 'Password': '', 'Times Password Leaked': '', 'Times Email Leaked': '',
                   'Domains': '', 'Dates': '', 'Most Recent': '', 'Data Types Leaked': ''}

    def query(self):
        import csv
        import time
        # create the csv file to use as output
        with open(self.o_f + '.csv', 'w', newline='') as f:
            q_writer = csv.DictWriter(f, fieldnames=self.qv.keys())
            q_writer.writeheader()
            result = self.i_f.parse_file()
            for i in result: # for each item in the list, apply the right value
                key = self.i_f.result[i]
                self.qv.update({'Email': key['email']})
                self.qv.update({'Password': key['password']})
                bpq = BluePages(key['email'])
                if bpq['AccountStatus'] != 'Not Found': # calls the bluepages class to check if found
                    self.qv.update({'AccountStatus': str(bpq['AccountStatus'])})
                    self.qv.update({'AccountType': str(bpq['AccountType'])})
                    self.qv.update({'Last Password Change': str(bpq['PasswordTimeStamp'])})
                    r_email = self.qe(key['email'])

                    if r_email != 'Not Found': # if the email is found in HIBP
                    # creating arrays to store the HIBP results
                        domains = []
                        date_domain = []
                        date = []
                        data_type = []
                        for r in r_email:
                            domains.append(r['Domain'])
                            date_domain.append((r['Domain'], r['BreachDate']))
                            date.append(r['BreachDate'])
                            for d in r['DataClasses']:
                                data_type.append(d)
                        date.sort(reverse=True)
                        self.qv.update({'Times Email Leaked': len(domains)})
                        self.qv.update({'Domains': str(domains).replace(',', ' |').strip('[').strip(']')})
                        self.qv.update({'Dates': str(date_domain).replace(',', ' |').strip('[').strip(']')})
                        self.qv.update({'Most Recent': date[0]})
                        self.qv.update({'Data Types Leaked': str(set(data_type)).replace(',', ' |').strip('{').strip('}')})

                    if r_email == 'Not Found': # if the email is not in HIBP
                        self.qv.update({'Times Email Leaked': '0'})
                        self.qv.update({'Domains': 'N/A'})
                        self.qv.update({'Dates': 'N/A'})
                        self.qv.update({'Most Recent': 'N/A'})
                        self.qv.update({'Data Types Leaked': 'N/A'})

                    if str(key['hash']): # check number times the password has been found in HIBP
                        q_password = self.qp(str(key['hash'][:5]))
                        r_hash = q_password.split('\n')
                        orig_hash = str(key['hash'][5:])
                        for r in r_hash:
                            a = r.rstrip('\r')
                            b = a.split(':')
                            if str(b[0]) == str(orig_hash):
                                self.qv.update({'Times Password Leaked': str(b[1])})
                    else:
                        self.qv.update({'Times Password Leaked': '0'})
                    #time.sleep(1)
                else: #if email is not found in LDAP, write N/A to all fields for that account
                    self.qv.update({'AccountStatus': 'Not Found', 'AccountType': 'N/A', 'Last Password Change': 'N/A', 'Times Password Leaked': 'N/A', 'Times Email Leaked': 'N/A',
                   'Domains': 'N/A', 'Dates': 'N/A', 'Most Recent': 'N/A', 'Data Types Leaked': 'N/A'})
                q_writer.writerow(self.qv)


def parse_commandline():
    # Parses Commandline input for type of search to make, input file, and output path
    args = {}
    import argparse
    parser = argparse.ArgumentParser(prog='LeakChecker',
                                     usage='Check credentials against the Have I Been PWND API')

    parser.add_argument('-s', '--single', dest='single', default=False, action='store_true',
                        help=(
                            'Search Have I Been PWND for single criteria.\n'
                            'ie. Just Emails or Just Passwords'
                        ))
    parser.add_argument('-m', '--multiple', dest='multiple', default=False, action='store_true',
                        help=(
                            'Search Have I Been PWND for multiple criteria.\n'
                            'ie. Emails and Passwords'
                        ))
    parser.add_argument('-IF', '--input_file', dest='input', required=True,
                        help=(
                            'File containing criteria to search for.\n'
                            'Example: criteria.txt\n'
                            'For single item; ie "emails" then each line must contain a single email.\n'
                            'For both; each line must contain BOTH the email and password separated by a comma.'
                        ))
    parser.add_argument('-OP', '--output_path', dest='output', default=os.getcwd() + '/',
                        help=(
                            'Path to save results file.'
                        ))
    arguments = parser.parse_args()

    if arguments.single is True:
        args['Type'] = 'single'
    if arguments.multiple is True:
        args['Type'] = 'multiple'
    args['Input_File'] = arguments.input
    args['Path'] = arguments.output + args['Input_File']
    return args


def main():
    args = parse_commandline()
    q = Query(args['Input_File'], args['Path'])
    q.query()


if __name__ == '__main__':
    main()
