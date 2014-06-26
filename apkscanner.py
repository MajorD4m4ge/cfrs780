__author__ = 'Liteman'

#ConfigParser code provided by TKhan
#Code customized and extended with error-checking and additional arguments
#imports virt.py which requires the requests library be installed http://docs.python-requests.org/en/latest/
#requires mainintent.py provided by TKhan -- Copied and mofified from --> http://www.bulbsecurity.com/backdooring-apks-programmatically-2/


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
import virt         #https://github.com/subbyte/virustotal/blob/master/virt.py
import json
import logging
import time
import mainintent as mi


#Global Values
VERSION = '0.9'
MAX_PATH = 260
cfgfile = "config.ini"
outpath = ""  #set by config.ini or command-line argument
target = ""   #set by config.ini or command-line argument
system = platform.platform()
architecture = platform.architecture()[0]

def unzip(apkfile):
    global target

    #Check for / create directory "unpacked" in Target location
    if not os.path.isdir(target + "\\unpacked"):
        os.mkdir(target + "\\unpacked")

    unzipfolder = target + "\\unpacked\\" + apkfile.split("\\")[-1].replace('.','-')

    with zipfile.ZipFile(apkfile) as zf:
        zf.extractall(unzipfolder)

    return os.path.abspath(unzipfolder)

def extract(apkfile):
    #TODO -- Reevaulate this function. Can this be replaced by unzip?
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
        print('\t[+] Checking dependencies...')

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
            if path.exists(value):
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
            if path.exists(value):
                if verbose >= 2:
                    print('\t [+]  ', value, '|')
            else:
                print('\t| [-] ', value, '|')
                missing += '\n| [-]:   '
                missing += value

    print()
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

def folderCheck(outdir, targdir, bulk=False):
    global outpath
    global target

    print("[+] Checking Folders")



    #if outpath and target were not specified on the command line, fall back to config file and
    config = parseConfig()
    if outdir:
        if outpath == "":
            if 'Windows' in system:
                value = config.get('Windows-Settings', 'outpath')
                if value == "":
                    print('\tOutput Directory not set, using current working directory')
                    outpath = os.getcwd() + "\\Reports"
                else:
                    outpath = value

            change = query_yes_no("\tOutput directory set to: \"" + outpath + "\" \n\tDo you wish to change it?", "no")
            if (change):
                outpath = input("\tEnter a new output directory path: ")
                print("\tOutput directory changed to: " + outpath)
                print()

    if targdir:
        if target == "":
            if 'Windows' in system:
                value = config.get('Windows-Settings', 'target')
                if value == "":
                    print('\tTarget directory not set, using current working directory')
                    target = os.getcwd() + "\\Target"
                else:
                    target = value

            change = query_yes_no("\n\tTarget directory set to: \"" + target + "\" \n\tDo you wish to change it?", "no")
            if (change):
                target = input("\tEnter a new target directory: ")

    #if outpath does not exist, create it?
    #if bulk_extractor is used, do not create the output directory -- Bulk Extractor will create it
    if outdir:
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
    if targdir:
        if not path.exists(target):
            print("[-] Folder Check Failed")
            print("\tThe specified target path does not exist. \n\tExiting...")
            sys.exit(1)

    print("[+] Folder Check Complete")

#Verify config.ini exists
def testConfig(file):
    global cfgfile

    if file is not None:
        cfgfile = file

    try:
        f = open(cfgfile, 'rb')
    except IOError:
        print("Configuration File Not Found: " + str(cfgfile))
        print("Verify config.ini exists with this python file or use the -F option to specify a new location")
        sys.exit(1)

    print("Config.ini Found. Reading..")

    f.close()


#Assignment1 Main
def assignOne(args):

    global debug
    global cfgfile
    global outpath
    global target
    verbose = 0


    testConfig(args.config)

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
    folderCheck(True, True)
    print("[+] Folder Check Complete")

    #Commence searching
    #If bulk extractor is used, send True to folderCheck()
    if args.apk:
        #update outpath and target
        print()
        print("[+] APK Specified. Unzipping...")
        extract(args.apk)


    if args.usebulk:
        print()
        bulkScan(verbose)

    if args.findip:
        findIPs()

    if args.findurl:
        findURLs()

def getScanTable(scans):

    # Define the template for string display.
    # Fields: AV-Vendor Version Detected Update Result
    # Separator: ----------

    displayTemplate = "{0:22}{1:10}{2:35}{3:10}{4:10}"
    tableArray = [('AV-Vendor', 'Detected', 'Result', 'Updated', 'Version'),('-'*18, '-'*8,'-'*20,'-'*8,'-'*8)]

    tempStr = ""
    for vendor, results in sorted(scans.items()):
        tup = (vendor,)
        for key, value in sorted(results.items()):
            tup = tup + (str(value),)
        tableArray.append(tup)

    tempStr = tempStr + displayTemplate.format(*tableArray[0]) + "\n"
    tempStr = tempStr + displayTemplate.format(*tableArray[1]) + "\n"

    for tup in tableArray[2:]:
        tempStr = tempStr + displayTemplate.format(*tup) + "\n"

    return tempStr

def listDetected(scans):

    displayTemplate = "{0:22}{1:35}"
    tableArray = [('AV-Vendor', 'Result'),('-'*18,'-'*20)]

    tempStr = ""

    for vendor, results in sorted(scans.items()):
        tup = (vendor,)
        if results.get('detected'):
            tup = tup + (results.get('result'),)
            tableArray.append(tup)

    tempStr = tempStr + "\t\t" + displayTemplate.format(*tableArray[0]) + "\n"
    tempStr = tempStr + "\t\t" + displayTemplate.format(*tableArray[1]) + "\n"

    for tup in tableArray[2:]:
        tempStr = tempStr + "\t\t" + displayTemplate.format(*tup) + "\n"

    print(tempStr)

def vtScan(args):

    global outpath
    verbose = 0

    if args.verbose:
        verbose = args.verbose

    testConfig(args.config)

    folderCheck(True, False)

    print("\n[+] Submitting file(s) to VirusTotal\n\tPath: " + args.file)

    #Create VirusTotal object from virt
    vt = virt.VirusTotal()

    #parse API Key from config.ini
    config = parseConfig()
    if config.get('api-keys', 'virustotal') is '':
            print("\t[-]Error: You must add your VirusTotal API Key in config.ini ")
            sys.exit(1)
    else:
        vt.apikey = config.get('api-keys', 'virustotal')

    if verbose > 1:
        print("\tAPI Key: " + vt.apikey)

    #if the output directory does not have a VirusTotal folder - create it
    if not os.path.isdir(os.path.join(outpath, "VirusTotal")):
        os.mkdir(os.path.join(outpath, "VirusTotal"))

    #turn on virt logging
    filelog = logging.FileHandler(outpath + "\\VirusTotal\\vtlog.txt")
    filelog.setFormatter(logging.Formatter("[%(asctime)s %(levelname)s] %(message)s", datefmt="%m/%d/%Y %I:%M:%S"))
    vt.logger.addHandler(filelog)

    #add support for single file or multiple files - using virt.list_all_files()
    filenames = virt.list_all_files(args.file)

    #keep a dict of sentFiles and response codes. Used later to loop through and request scan reports
    sentFiles = {}
    for filename in filenames:
        shahash = virt.sha256sum(filename)

        #request report and check status code
        #1 = Report available  -2 = VT Has never seen the file
        print("\tRequesting report for: " + os.path.basename(filename))
        res = vt.retrieve_report(shahash)
        resmap = json.loads(res.text)

        if resmap['response_code'] == -2 or args.force:
            print("\tSending file to VT: " + os.path.basename(filename))
            response = vt.send_files(virt.list_all_files(filename))


        reportName = vtReport(filename, resmap)
        if verbose > 0:
            print("\t\t" + os.path.basename(filename) + " results: ")
            print("\t\t" + resmap['permalink'])
            if resmap['positives'] > 0:
                print("\t\tSample detected by: ")
                listDetected(resmap['scans'])
            else:
                print("\t\tSample not flagged as malicious by any of the " + str(resmap['total']) + " AV-Vendors checked")
                print()
        print("\t" + os.path.basename(filename) + " report saved to " + outpath + "\\VirusTotal\\" + reportName)
        print()

    print("[+] VirusTotal Request(s) Complete")
    print("\t - Log file: " + outpath + "\\VirusTotal\\vtlog.txt" )


def vtReport(filename, resmap):


    reportName = os.path.basename(filename) + "-" + resmap.get('sha256')[:6] + resmap.get('sha256')[-6:] + "-" + resmap["scan_date"].split()[0] + ".txt"

    if not os.path.exists(outpath + "\\VirusTotal\\" + "hashlist.txt"):
        f = open(outpath + "\\VirusTotal\\" + "hashlist.txt", 'w')
        f.close()


    with open(outpath + "\\VirusTotal\\" + reportName, 'w') as report:
        report.write("File Scanned: " + filename + "\n")
        report.write("VirusTotal: " + resmap["permalink"] + "\n")
        report.write("Hashes:\n")
        report.write("\tMD5: " + resmap["md5"] + "\n")
        report.write("\tSHA1: " + resmap["sha1"] + "\n")
        report.write("\tSHA256: " + resmap["sha256"] + "\n")
        report.write("\n")
        report.write("Scan Date: " + resmap["scan_date"].split()[0] + "\n")
        report.write("Response Code " + str(resmap["response_code"]) + "\n")
        report.write("Positives: " + str(resmap["positives"]) + "\n")
        report.write("Total: " + str(resmap["total"]) + "\n")
        report.write("Scans: " + "\n")
        report.write(getScanTable(resmap['scans']))

    with open(outpath + "\\VirusTotal\\" + "hashlist.txt", 'a') as hashlist:
        hashlist.write("\nSHA256\t" + reportName + "\t" + virt.sha256sum(outpath + "\\VirusTotal\\" + reportName) )

    return reportName

def decodeapk(apkfile):
    global target

    #Check for / create directory "decoded" in Target location
    decodedpath = target + "\\decoded"
    if not os.path.isdir(decodedpath):
        os.mkdir(decodedpath)

    #find path to apktool
    config = parseConfig()
    apktoolpath = config.get('Windows-Tools', 'apktool')

    #build command for apktool
    decodedapkpath = os.path.join(decodedpath, apkfile.split("\\")[-1].replace('.', '-'))
    apkcmd = apktoolpath + "\\apktool.bat d " + apkfile + " " + decodedapkpath
    subprocess.call(apkcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    return decodedapkpath


def testavd(args):
    '''print(args.name)
    print(args.size)
    print(args.apk)
    print(args.intent)
    print(args.package)
    print(args.timeout)
    '''
    verbose = 0
    if args.verbose:
        verbose = args.verbose

    testConfig(args.config)
    folderCheck(True, True)
    tempdir = target + "\\Temp"

    print("[+] Starting up AVD Emulator")
    print()

    depCheck(verbose)

    #Read config.ini settings for AVD and SDCARD paramters
    config = parseConfig()

    #Prepare AVD Settings
    if verbose > 0:
        print("\t[+] AVD and SDCARD Settings")
        for key in config['android']:
            print("\t\t" + str(key) + "\tValue: " + config.get('android', key))

    if not args.name:
        avdname = "testavd_" + os.path.basename(args.apk).replace('.', '-')
    else:
        avdname = args.name

    sdname = avdname + "_sdcard.img"


    print("\t\tAVD Name set to: " + avdname)
    print("\t\tSDCard Name set to: " + sdname)

    if not os.path.isdir(tempdir):
        os.mkdir(tempdir)
    print("\t\tFiles placed in " + tempdir)

    #Read Andoird Settings from config.ini
    andsdktoolpath = config.get('Windows-Tools', 'andsdktools')
    apiversion = config.get('android', 'apiversion')
    andplatform = config.get('android', 'vplatform')
    sdcardsize = config.get('android', 'sdcardsize')
    partsize = config.get('android', 'partitionsize')
    runtime = config.get('android', 'runtime')

    #convert runtime to float
    try:
        runtime = float(runtime)
    except:
        print("[-] Error: Not able to read android runtime from " + os.path.abspath(cfgfile))

    #Get MainIntent from Target App
    ## args.apk holds the apk file path
    ## use mainintents.py
    ## mainintent.py requires an extracted apk folder
    ## the apk must be decoded by apktool before it can be parsed by mainintent
    ## Usage for apktool:
    ##  Usage: apktool [-q|--quiet OR -v|--verbose] COMMAND [...]
    ##
    ##  COMMANDs are:
    ##
    ##  d[ecode] [OPTS] <file.apk> [<dir>]
    ##    Decode <file.apk> to <dir>.

    print()
    print("\t[+] Decoding APK ")

    decodedapk = decodeapk(args.apk)
    package, mainact = mi.printmainintent(decodedapk)
    mainintent = package + "/" + mainact
    print("\t\tMainintent: " + mainintent)
    print()




    #Create AVD
    ## Command Construction
    ## F:\School\Tools\ADTBundle\sdk\tools\android.bat create avd -n <name> -t <api> --abi <platform>
    ## F:\School\Tools\ADTBundle\sdk\tools\android.bat create avd -n newAVD -t android-17 --abi default/x86

    print()
    print("\t[+] Creating AVD ")
    print("\t\tAVD Name: " + avdname)

    #handle the interactive input from android.bat
    createcmd = "echo no | "

    createcmd += andsdktoolpath + "\\android.bat create avd -n " + avdname + " -t " + apiversion + " --abi " + andplatform + " -p " + tempdir + "\\avd"

    if verbose > 1:
        print("Create AVD Command: " + createcmd)

    subprocess.call(createcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    #Create SDCARD
    ##Command construction
    ## F:\School\Tools\ADTBundle\sdk\tools\mksdcard -l <label> <size>M <sd image name>
    ## F:\School\Tools\ADTBundle\sdk\tools\mksdcard -l cfrs 1024M avdimage.img
    print()
    print("\t[+] Creating SD Card Image ")
    mksdcmd = andsdktoolpath + "\\mksdcard -l " + avdname[:-3] + " " + sdcardsize + " " + os.path.join(tempdir, sdname)
    if verbose > 1:
        print("Create SD Command: " + mksdcmd)

    subprocess.call(mksdcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


    #Start AVD
    ## Command Construction
    ## F:\School\Tools\ADTBundle\sdk\tools\emulator -avd <name> -partition-size 512 -noaudio -no-snapshot -sdcard <avd image name>
    ## F:\School\Tools\ADTBundle\sdk\tools\emulator -avd newAVD -partition-size 512 -noaudio -no-snapshot -sdcard avdimage.img

    print("\t[+] Starting Emulator ")
    startcmd = andsdktoolpath + "\\emulator-x86.exe -avd " + avdname + " -partition-size " + partsize + " -noaudio "
    startcmd += "-no-snapshot -sdcard " + os.path.join(tempdir, sdname)

    if verbose > 1:
        print("\t\tStart AVD command: " + startcmd)

    #Start the Process, then capture the PID
    avdproc = subprocess.Popen(startcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    avdpid = str(avdproc.pid)
    print("\t\tEmulator PID: " + avdpid)

    #allow emulator time to load
    time.sleep(20)

    if not args.manual:
        #Remount emulator file system
        #TODO
        print()
        print("\t[+] Remounting Filesystem to Read/Write")

        # Install and Launch App and Sleep
        ##TODO
        ##
        print()
        print("\t[+] Installing APK")





        print("\t\tRunning APK for " + str(runtime) + " Seconds")
        time.sleep(runtime)


        #Kill AVD Process
        ##
        print("\t\tKilling AVD Process: " + avdpid)
        subprocess.call("taskkill /PID " + avdpid,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        #Begin Cleanup
        ##
        print("\t[+] Cleaning up...")
        print("\t\tDeleting AVD: " + avdname)
        print("\t\tDeleting SDCard: " + os.path.join(tempdir, sdname))

        delcmd = andsdktoolpath + "\\android.bat delete avd -n " + avdname

        if verbose > 1:
            print("\t\tDelete AVD Command: " + delcmd)

        subprocess.call(delcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


        os.remove(os.path.join(tempdir, sdname))

        print("[+] App Test Complete.")
    else:
        print("[+] Emulator start up complete.")
        print("\tDon't forget to delete the AVD when finished")



#Parse the command line arguments.
def main(argv):

    global debug
    global cfgfile
    global outpath
    global target
    verbose = 0


    subprocess.call("cls", shell=True)

    print()
    print("APK Scanner - Version " + VERSION)
    print()

    parser = argparse.ArgumentParser(description="", add_help=True)
    subparsers = parser.add_subparsers()

    #Subparser for Assignment1
    parser_assignment1 = subparsers.add_parser('assign1')
    parser_assignment1.add_argument('-c', '--config', help='The file that contains configuration settings', metavar='file', required=False)
    parser_assignment1.add_argument('-f', '--apk', help='Specify an apk file to unpack and search', metavar='file', required=False)
    parser_assignment1.add_argument('-b', '--usebulk', help='Use Bulk_Extractor to perform scans (Cannot be used with -i or -u', action='store_true', required=False)
    parser_assignment1.add_argument('-o', '--output', help='The location to save output file', metavar='dir', required=False)
    parser_assignment1.add_argument('-t', '--target', help='The unpacked apk directory to scan. if -f is used, the apk will be unpacked here', metavar='dir', required=False)
    parser_assignment1.add_argument('-i', '--findip', help='Search for IP Addresses in target files', action='store_true', required=False)
    parser_assignment1.add_argument('-u', '--findurl', help='Search for URLs in target files', action='store_true', required=False)
    parser_assignment1.add_argument('-v', '--verbose', help='The level of debugging.', type=int, required=False)
    parser_assignment1.add_argument('--showconfig', help='Print contents of config.ini', action='store_true', required=False)
    parser_assignment1.add_argument('--version', action='version', version='%(prog)s 0.8')
    parser_assignment1.set_defaults(func=assignOne)

    #extract command
    parser_unzip = subparsers.add_parser('unzip')
    #TODO

    #bulkscan command
    parser_bulkscan = subparsers.add_parser('bulkscan')
    #TODO

    #hashpull command
    parser_adbpull = subparsers.add_parser('adbpull')
    #TODO

    #testavd command
    parser_testavd = subparsers.add_parser('testavd')
    #TODO
    parser_testavd.add_argument('-m', '--manual', help="Create and start the emulator only", action='store_true', required=False)
    parser_testavd.add_argument('-c', '--config', help="Specify alternative config.ini file", metavar="PATH", required=False)
    parser_testavd.add_argument('-n', '--name', help="Specify the name for the AVD file", required=False)
    parser_testavd.add_argument('-s', '--size', help="Size of the SD Card (Default is 1024)", required=False)
    parser_testavd.add_argument('-a', '--apk', help="APK File to load and test", metavar='PATH', required=False)
    parser_testavd.add_argument('-t', '--timeout', help="Kill AVD process after -t seconds (Default 30)", metavar='SECONDS', required=False)
    parser_testavd.add_argument('-p', '--package', help="Package name of APK", metavar='NAME', required=False)
    parser_testavd.add_argument('-i', '--intent', help="Main intent of APK", metavar='NAME', required=False)
    parser_testavd.add_argument('-v', '--verbose', help="The level of debugging", type=int)
    parser_testavd.set_defaults(func=testavd)


    #virustotal command
    #TODO
    parser_virustotal = subparsers.add_parser('virustotal')
    parser_virustotal.add_argument('-c', '--config', help="Specify alternative config.ini file", metavar="PATH", required=False)
    parser_virustotal.add_argument('-f', '--file', help='Specify the path to a file or directory of files to send to VirusTotal', metavar='PATH', required=True)
    parser_virustotal.add_argument('--force', help='Send file to VirusTotal even a report is available', action='store_true', required=False)
    parser_virustotal.add_argument('-v', '--verbose', help='The level of debugging.', type=int, required=False)
    parser_virustotal.set_defaults(func=vtScan)

    args = parser.parse_args()
    args.func(args)






main(sys.argv[1:])