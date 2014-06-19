__author__ = 'Liteman'

#Original Code provided by TKhan in GMU CFRS780 course
#Code customized and extended with error-checking and additional arguments
#Checks for existence of dependencies (executable files, Python modules).
#Returns True if all dependencies are present; otherwise, returns False and prints missing files.


import sys
from os import path
import os
import platform     #https://docs.python.org/2/library/platform.html
import configparser #https://docs.python.org/2/library/configparser.html
import argparse     #http://docs.python.org/3.4/library/argparse.html
import re
import socket
import subprocess
import zipfile


#Global Values
MAX_PATH = 260
cfgfile = "config.ini"
outpath = ""  #set by config.ini or command-line argument
target = ""   #set by config.ini or command-line argument
system = platform.platform()
architecture = platform.architecture()[0]

def unzip(apkfile):
    global outpath
    global target

    #does the apk file exist? If so, append the file name to the end of outpath and target
    if not os.path.exists(apkfile):
        print("Cannot find the APK file specified: \n" + apkfile)
        print("Exiting...")
        sys.exit(1)
    else:
        target = os.path.join(target, apkfile.split("\\")[-1])
        target = target.replace(".", "-")
        print("\t[+] Updated Target Path: " + target)
        outpath = os.path.join(outpath, apkfile.split("\\")[-1])
        outpath = outpath.replace(".", "-")
        print("\t[+] Updated Report Path: " + outpath)

    with zipfile.ZipFile(apkfile) as zf:
        zf.extractall(target)

    print("[+] Unzip complete.")


def bulkScan(verbose):
    global outpath
    global target
    global system

    config = parseConfig()

    if 'Windows' in system:
        bulkcmd = config.get('Windows-Tools', '32_bulk')
    if 'Linux' in system:
        bulkcmd = config.get('Linux-Tools', '32_bulk')

    bulkcmd = "\"" + bulkcmd + "\"" + " -o " + outpath + " -R " + target

    print("[+] Running Bulk Extractor...")
    try:
        output = subprocess.Popen(bulkcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if(verbose > 0):
            for line in output.stdout.readlines():
                print(line.decode("ASCII").rstrip())

    except:
        print("There was a problem with bulk_extractor.")

    print("[+] Bulk Extractor Completed")

def findURLs():
    global cfgfile
    global target

    print("Find URL Flag Set: Searching..\n\n")

    config = parseConfig()
    with open(os.path.join(outpath,'URLsearch.txt'), 'w') as dest:
        for key in config['SearchesRegex-URL']:
            pattern = config.get('SearchesRegex-URL', key)[1:-1]
            print("\nUsing Pattern: " + key + ": " + pattern + "\n")
            dest.write("\nPattern: " + key + ": " + pattern + "\n\n")
            for root, subs, files in os.walk(target):
                for file in files:
                    lineCnt = 1
                    print("Reading file: " + os.path.join(root,file))
                    with open(os.path.join(root,file), 'rb') as f:
                        for line in f.readlines():
                            #print(line)
                            match = re.search(pattern, str(line))
                            if(match):
                                #print(f.name + ": Line " + str(lineCnt) + ", Offset " + str(match.start()) + ": " + match.group())
                                dest.write(f.name + ": Line " + str(lineCnt) + ", Offset " + str(match.start()) + ": " + match.group()+"\r\n")
                            lineCnt += 1
                    f.close()

def valid_ip(address): #http://stackoverflow.com/questions/11264005/using-a-regex-to-match-ip-addresses-in-python
    try:
        socket.inet_aton(address)
        return True
    except:
        return False

def findIPs():
    global cfgfile
    global target

    print("Find IP Flag Set: Searching..\n\n")

    config = parseConfig()
    with open(os.path.join(outpath,'IPsearch.txt'), 'w') as dest:
        for key in config['SearchesRegex-IP']:
            pattern = config.get('SearchesRegex-IP', key)[1:-1]
            print("\nUsing Pattern: " + key + ": " + pattern + "\n")
            dest.write("\nPattern: " + key + ": " + pattern + "\n\n")
            for root, subs, files in os.walk(target):
                for file in files:
                    lineCnt = 1
                    print("Reading file: " + os.path.join(root,file))
                    with open(os.path.join(root,file), 'rb') as f:
                        for line in f.readlines():
                            #print(line)
                            match = re.search(pattern, str(line))
                            if(match) and valid_ip(match.group()):
                                #print(f.name + ": Line " + str(lineCnt) + ", Offset " + str(match.start()) + ": " + match.group())
                                dest.write(f.name + ": Line " + str(lineCnt) + ", Offset " + str(match.start()) + ": " + match.group()+"\r\n")
                            lineCnt += 1
                    f.close()


def query_yes_no(question, default="yes"): #code from http://stackoverflow.com/questions/3041986/python-command-line-yes-no-input
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes":True,   "y":True,  "ye":True,
             "no":False,     "n":False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")


def parseConfig():
    global cfgfile
    config = configparser.ConfigParser()
    config.read(cfgfile)
    return config

#Parse the ini file to check whether dependencies are present.
def depCheck(verbose):
    global cfgfile

    if verbose >= 1:
        print('Entering Dependency Check:')

    if verbose >= 2:
        print('\tConfig file passed in:' + str(cfgfile))

    #Declare list of missing executables and/or modules.
    missing = '|[-] Missing the following:'
    isMissing = False

    #Determine system: 'nt' for Windows, 'posix' for *nix, Mac OSX
    system = platform.platform()

    #Determine 32-bit vs. 64-bit architecture
    if platform.architecture()[0] == '64bit':
        architecture = 64
    elif platform.architecture()[0] == '32bit':
        architecture = 32

    #Read the config file for parsing
    config = parseConfig()

    #debug statements
    #print(config.sections())
    #sys.exit(0)

    if 'Windows' in system:
        for key in config['Windows-Tools']:
            value = config.get('Windows-Tools', key)
            if path.isfile(value):
                if verbose >= 2:
                    print('\t| [+]  ', value, '|')
            else:
                print('\t| [-] ', value, '|')
                missing += '\n| [-]:   '
                missing += value
                isMissing = True

    elif 'Linux' in system:
        for key in config['Linux-Tools']:
            value = config.get('Linux-Tools', key)
            if path.isfile(value):
                if verbose >= 2:
                    print('\t [+]  ', value, '|')
            else:
                print('\t| [-] ', value, '|')
                missing += '\n| [-]:   '
                missing += value

    #Return True if all dependencies are present; otherwise, return False.
    if (isMissing):
        return False
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

def folderCheck(bulk=False):
    global outpath
    global target

    #if outpath and target were not specified on the command line, fall back to config file and
    # verify if user wants to continue
    config = parseConfig()
    if outpath == "":
        if 'Windows' in system:
            value = config.get('Windows-Settings', 'outpath')
            if value == "":
                print('\tOutput Directory not set, using current working directory')
                outpath = os.getcwd() + "\\Reports"
            else:
                outpath = value

        change = query_yes_no("\tOutput directory set to: \"" + outpath + "\" Do you wish to change it?", "no")
        if (change):
            outpath = input("\tEnter a new output directory path: ")
            print("\tOutput directory changed to: " + outpath)
            print()

    if target == "":
        if 'Windows' in system:
            value = config.get('Windows-Settings', 'target')
            if value == "":
                print('\tTarget directory not set, using current working directory')
                target = os.getcwd() + "\\Target"
            else:
                target = value

        change = query_yes_no("\tTarget directory set to: \"" + target + "\" Do you wish to change it?", "no")
        if (change):
            target = input("\tEnter a new target directory: ")

    #if outpath does not exist, create it?
    #if bulk_extractor is used, do not create the output directory -- Bulk Extractor will create it
    if not bulk:
        if not path.exists(outpath):
            create = query_yes_no("\tThe specified Output Directory does not exist. \nDo you wish to create it?")
            if (create):
                try:
                    os.mkdir(outpath)
                except:
                    print("\tUnable to create the output directory. Exiting...")
                    sys.exit(1)
            else:
                print("[-] Folder Check Failed")
                print("\tOutput directory does not exist. Cannot proceed. Specify a valid directory in config.ini or using the -o argument")
                sys.exit(1)

    #if target does not exist - present error and exit
    if not path.exists(target):
        print("[-] Folder Check Failed")
        print("\tThe specified target scan directory does not exist. \nVerify the location of the unpacked APK and try again.\nExiting...")
        sys.exit(1)


    proceed = query_yes_no("\n\tOutput Directory: " + outpath + \
                                    "\n\tTarget Directory: " + target + "\n\tDo you wish to proceed?")

    if not proceed:
        print("\tUser does not wish to proceed. Exiting...")
        sys.exit(1)

#Parse the command line arguments.
def main(argv):

    global debug
    global cfgfile
    global outpath
    global target
    verbose = 0

    parser = argparse.ArgumentParser(description="Check whether required programs and modules exist.", add_help=True)
    parser.add_argument('-c', '--config', help='The file that contains configuration settings', required=False)
    parser.add_argument('-f', '--apk', help='Specify an apk file to unpack and search', required=False)
    parser.add_argument('-b', '--usebulk', help='Use Bulk_Extractor to perform scans (Cannot be used with -i or -u', action='store_true', required=False)
    parser.add_argument('-o', '--output', help='The location to save output file', required=False)
    parser.add_argument('-t', '--target', help='The unpacked apk directory to scan. if -f is used, the apk will be unpacked here', required=False)
    parser.add_argument('-i', '--findip', help='Search for IP Addresses in target files', action='store_true', required=False)
    parser.add_argument('-u', '--findurl', help='Search for URLs in target files', action='store_true', required=False)
    parser.add_argument('-v', '--verbose', help='The level of debugging.', type=int, required=False)
    parser.add_argument('--showconfig', help='Print contents of config.ini', action='store_true', required=False)
    parser.add_argument('--version', action='version', version='%(prog)s 0.5')

    args = parser.parse_args()
    if args.config:
        cfgfile = args.file

    try:
        f = open(cfgfile, 'rb')
    except IOError:
        print("Configuration File Not Found: " + str(cfgfile))
        print("Verify config.ini exists with this python file or use the -F option to specify a new location")
        sys.exit(1)

    f.close()

    if args.verbose:
        verbose = args.verbose

    if verbose >= 1:
        print('Entering Main:')

    if args.showconfig:
            printConfig(cfgfile)
            sys.exit(0)

    value = depCheck(verbose)

    if not value:
        print("Required tools are missing. If these tools do exist, you can edit config.ini with the tool location. Otherwise, please install the required tools and retry.")
        sys.exit(1)
    else:
        print("\n[+]Dependency Check Successful!\n")

    #Verify target and output locations
    if args.output:
        outpath = args.output

    if args.target:
        target = args.target

    print("[+] Checking Folders")
    folderCheck()
    print("[+] Folder Check Complete")

    #Commence searching
    #If bulk extractor is used, send True to folderCheck()
    if args.apk:
        #update outpath and target
        print()
        print("[+] APK Specified. Unzipping...")
        unzip(args.apk)


    if args.usebulk:
        print()
        bulkScan(verbose)

    if args.findip:
        findIPs()

    if args.findurl:
        findURLs()



main(sys.argv[1:])