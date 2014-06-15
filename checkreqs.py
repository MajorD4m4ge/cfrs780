__author__ = 'Liteman'

#Original Code provided by TKhan in GMU CFRS780 course
#Code customized with error-checking and additional arguments
#Checks for existence of dependencies (executable files, Python modules).
#Returns True if all dependencies are present; otherwise, returns False and prints missing files.

import sys
from os import path
import platform     #https://docs.python.org/2/library/platform.html
import configparser #https://docs.python.org/2/library/configparser.html
import argparse     #http://docs.python.org/3.4/library/argparse.html


#Parse the ini file to check whether dependencies are present.
def parse(file, verbose):

    if verbose >= 1:
        print('Entering parse:')

    if verbose >= 2:
        print('\tConfig file passed in:' + str(file))

    #Declare list of missing executables and/or modules.
    missing = '|[-] Missing the following:'

    #Determine system: 'nt' for Windows, 'posix' for *nix, Mac OSX
    system = platform.platform()

    #Determine 32-bit vs. 64-bit architecture
    if platform.architecture()[0] == '64bit':
        architecture = 64
    elif platform.architecture()[0] == '32bit':
        architecture = 32

    #Read the config file for parsing
    config = configparser.ConfigParser()
    config.read(file)

    #debug statements
    #print(config.sections())
    #sys.exit(0)

    if 'Windows' in system:
        for key in config['Windows']:
            value = config.get('Windows', key)
            if path.isfile(value):
                if verbose >= 2:
                    print('\t| [+]  ', value, '|')
            else:
                print('\t| [-] ', value, '|')
                missing += '\n| [-]:   '
                missing += value

    elif 'Linux' in system:
        for key in config['Linux']:
            value = config.get('Linux', key)
            if path.isfile(value):
                if verbose >= 2:
                    print('\t [+]  ', value, '|')
            else:
                print('\t| [-] ', value, '|')
                missing += '\n| [-]:   '
                missing += value

    #Return True if all dependencies are present; otherwise, return False.
    if (len(missing)):
        return False, missing
    else:
        return True

def printConfig(file):
    f = open(file, 'rb')
    print()
    print('Tool Configuration from ' + str(file))
    print()
    for line in f.readlines():
        print(line.decode('ASCII').rstrip())
    f.close()


#Parse the command line arguments.
def main(argv):

    try:
        global debug
        verbose = 0
        file = 'config.ini'
        parser = argparse.ArgumentParser(description="Check whether required programs and modules exist.", add_help=True)
        parser.add_argument('-f', '--file', help='The file that contains paths for the required programs and modules.', required=False)
        parser.add_argument('-v', '--verbose', help='The level of debugging.', type=int, required=False)
        parser.add_argument('--showconfig', help='Print contents of config.ini', action='store_true', required=False)
        parser.add_argument('--version', action='version', version='%(prog)s 0.5')

        args = parser.parse_args()
        if args.file:
            file = args.file

        try:
            f = open(file, 'rb')
        except IOError:
            print("Configuration File Not Found: " + str(file))
            print("Verify the location of config.ini or use the -F option to specify a new location")
            sys.exit(1)

        f.close()

        if args.verbose:
            verbose = args.verbose

        if verbose >= 1:
            print('Entering Main:')

        if args.showconfig:
                printConfig(file)
                sys.exit(0)

        value, error = parse(file, verbose)
        return value, error

    except IOError:
        sys.exit('Error: File ' + str(file) + ' does not exist.')

main(sys.argv[1:])