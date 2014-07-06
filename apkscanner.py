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
import hashlib


#Global Values
VERSION = '0.9'
MAX_PATH = 260
cfgfile = "config.ini"
config = None
outpath = ""  #set by config.ini or command-line argument
target = ""   #set by config.ini or command-line argument
system = platform.platform()
architecture = platform.architecture()[0]


def md5sum(filename):

    with open(filename, 'rb') as f:
        m = hashlib.md5()
        while True:
            data = f.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

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

    print("[+] Running Bulk Extractor...")

    if 'Windows' in system:
        bulkcmd = config.get('Windows-Tools', '32_bulk')
    if 'Linux' in system:
        bulkcmd = config.get('Linux-Tools', '32_bulk')

    bulkcmd = "\"" + bulkcmd + "\"" + " -o " + outpath + " -R " + "\"" +  target + "\""
    if verbose > 1:
        print("\tBulk Command: " + bulkcmd)


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

    if verbose > 0:
        print()
        print('[+] Checking dependencies...')

    if verbose > 1:
        print('\tConfig file passed in:' + str(cfgfile))

    #Declare list of missing executables and/or modules.
    missing = '\t|[-] Missing the following:'
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

def decodeapk(apkfile, avdname, verbose):
    global outpath

    #Check for / create directory "decoded" in Target location
    decodedpath = outpath + "\\" + avdname + "\\decoded"
    if not os.path.isdir(decodedpath):
        os.mkdir(decodedpath)

    #find path to apktool
    apktoolpath = config.get('Windows-Tools', 'apktool')

    #build command for apktool
    #decodedapkpath = os.path.join(decodedpath, apkfile.split("\\")[-1].replace('.', '-'))

    #remove spaces from output path
    #decodedapkpath = decodedapkpath.replace(' ', '-')
    apkcmd = apktoolpath + "\\apktool.bat d -f -o " + decodedpath + " \"" + apkfile + "\""

    print("\t\tDecoded Path:" + decodedpath)
    if verbose > 1:
        print("\t\tAPK Command: " + apkcmd)

    subprocess.call(apkcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    return decodedpath

def getemulator(andplatformtools, verbose):

    choices = []
    rawoutput = subprocess.Popen(andplatformtools + "\\adb devices -l", shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in rawoutput.stdout.readlines():
        print(line.decode("ASCII"))

    print("Done with device list...Exiting")
    sys.exit()

def killavd(avdpid, avdname, sdname, tempdir, andsdktoolpath, verbose):

    #Kill AVD Process
    ##
    print("\tKilling Emulator Process: " + avdpid)
    subprocess.call("taskkill /PID " + avdpid, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    #Begin Cleanup
    ##
    print()
    print("[+] Cleaning up...")
    print("\tDeleting AVD: " + avdname)
    print("\tDeleting SDCard: " + os.path.join(tempdir, sdname))

    delcmd = andsdktoolpath + "\\android.bat delete avd -n " + avdname

    if verbose > 1:
        print("\tDelete AVD Command: " + delcmd)

    subprocess.call(delcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    os.remove(os.path.join(tempdir, sdname))


def listdevices(andplatformtools, verbose, count=False):
    '''
    :param andplatformtools: Path to ADB.exe
    :param count:  -- boolean value, if true return number of devices in list. if False return list of devices
    :param verbose:
    :return:
    '''
    output = subprocess.Popen(andplatformtools + "\\adb.exe devices -l", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2) #give Popen time to return
    results = []
    for line in output.stdout.readlines():
        results.append(line.decode("ASCII"))

    if count:
        return len(results) - 2 #if no devices are present, the list length is 2 lines. Subtract 2
    else:
        if verbose > 1:
            print("\t\tResults list \n\t\t\t" + str(results[1:]))
        return results[1:] #do not include the heading and blank line

def setstartmarker(andplatformtools, verbose):

    subprocess.call(andplatformtools + "\\adb shell touch /system/vendor/bin/starttime")

def gettouchedfiles(andplatformtools, verbose):
    '''

    :param andplatformtools: path to adb.exe
    :param verbose:
    :return: a list of the line-by-line output
    '''

    findcmd = 'find / \\( -type f -a -newer /system/vendor/bin/starttime \\) -o -type d -a \\( -name dev -o -name proc -o -name sys \\) -prune | grep -v -e \"^/dev$\" -e \"^/proc$\" -e \"^/sys$\"'

    list = []
    output = subprocess.Popen(andplatformtools + "\\adb shell /system/vendor/bin/busybox-i686 " + findcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for line in output.stdout.readlines():
        list.append(line.decode("ASCII").rstrip())

    return list

def processfiles(filelist, andplatformtools, avdname, verbose):
    global outpath


    savefilesdir = os.path.join(outpath, avdname) + "\\touched_files"

    #create directory to save files
    if not os.path.isdir(os.path.join(outpath, avdname)):
        os.mkdir(os.path.join(outpath, avdname))  # %OUTPATH%\<avdname>
        os.mkdir(savefilesdir)
    elif not os.path.isdir(savefilesdir): # %OUTPATH%\<avdname>\touched_files
        os.mkdir(savefilesdir)

    hashfile = savefilesdir + "\\hashes.txt"

    if not os.path.exists(hashfile):
        open(hashfile, 'w').close() #create hashes.txt for future writing


    for file in filelist:
        filename = file.split("/")[-1]
        adbpullcmd = andplatformtools + "\\adb pull " + file + " " + savefilesdir
        output = subprocess.Popen(adbpullcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if verbose > 0:
            for line in output.stdout.readlines():
                print("\t\t" + line.decode("ASCII").rstrip())
        with open(hashfile, 'a') as hash:
            hash.write(virt.sha256sum(os.path.join(savefilesdir, filename)) + "\t\t" + file + "\n")

def installapk(andplatformtools, apkfile, verbose):
    print()
    print("\t[+] Installing APK")

    installcmd = andplatformtools + "\\adb install " + "\"" + apkfile + "\""

    if verbose > 1:
        print("\t\tInstall APK Command: " + installcmd)

    subprocess.call(installcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def getinstallpath(andplatformtools, package, verbose):
    #find the installed apk on the device in the /data/app directory
    #file will be named with the package name + the version .apk
    #search /data/app and grep the package name
    print()
    print("\t[+] Locating installed APK")
    lscmd = andplatformtools + "\\adb shell ls /data/app | /system/vendor/bin/busybox-i686 grep -i " + package

    resultb = subprocess.Popen(lscmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    resultStr = resultb.stdout.read().decode("ASCII").rstrip()

    if package not in resultStr:
        print("\t\tInstalled APK not found in /data/app")
        return ''
    else:
        if verbose > 0:
            print("\t\tFound APK in /data/app" + resultStr)
        return "/data/app/" + resultStr



def testavd(args):
    global config
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

    tempdir = outpath + "\\temp"
    if not os.path.isdir(tempdir):
        os.mkdir(tempdir)

    depCheck(verbose)

    print("[+] Starting up AVD Emulator")
    print()

    #Read config.ini settings for AVD and SDCARD paramters
    config = parseConfig()

    #Read Andoird Settings from config.ini
    andsdktoolpath = config.get('Windows-Tools', 'andsdktools')
    andplatformtools = config.get('Windows-Tools', 'andplatformtools')
    apiversion = config.get('android', 'apiversion')
    andplatform = config.get('android', 'vplatform')
    sdcardsize = config.get('android', 'sdcardsize')
    partsize = config.get('android', 'partitionsize')
    runtime = config.get('android', 'runtime')
    busybox = config.get('Windows-Tools', 'busybox')

    #start adb running, if it isn't already
    subprocess.call(andplatformtools + "\\adb devices", shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if verbose > 0:
        print("\t[+] Android settings from config.ini")
        for key in config['android']:
            print("\t\t" + str(key) + "\tValue: " + config.get('android', key))
        print()

    if not args.manual: #if manual isn't specified args.apk must be set with -a
        #TODO validate the specified apk path
        if not args.apk:
            print("[-] Error - Missing argument: You must specify -m or -a <apk path>")
            sys.exit(1)

        if not args.name: #if -n wasn't used to specify name, use the name of the apk file
            avdname = "testavd_" + args.apk.split("\\")[-1].replace('.', '-') #remove periods
            avdname = avdname.replace(' ', '-') #remove spaces
        else:
            avdname = args.name
    elif not args.name:
        avdname = "testavd_Manual"  #-m is set, but -n (name of avd) is not set
    else:
        avdname = args.name #-m and -n are set

    sdname = avdname + "_sdcard.img"

    #create output directory specific to this avd
    if not os.path.isdir(os.path.join(outpath, avdname)):
        os.mkdir(os.path.join(outpath, avdname))  # %OUTPATH%\<avdname>


    print("\t\tAVD Name set to: " + avdname)
    print("\t\tSDCard Name set to: " + sdname)
    print("\t\tTemporary folder: " + tempdir)



    #convert runtime to float
    try:
        runtime = int(runtime)
    except:
        print("[-] Error: Not able to read android runtime from " + os.path.abspath(cfgfile))


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
        print("\t\tCreate AVD Command: " + createcmd)

    subprocess.call(createcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    #Create SDCARD
    ##Command construction
    ## F:\School\Tools\ADTBundle\sdk\tools\mksdcard -l <label> <size>M <sd image name>
    ## F:\School\Tools\ADTBundle\sdk\tools\mksdcard -l cfrs 1024M avdimage.img
    print()
    print("\t[+] Creating SD Card Image ")
    mksdcmd = andsdktoolpath + "\\mksdcard -l " + avdname + " " + sdcardsize + " " + os.path.join(tempdir, sdname)
    if verbose > 1:
        print("\t\tCreate SD Command: " + mksdcmd)

    subprocess.call(mksdcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    #Start AVD
    ## Command Construction
    ## F:\School\Tools\ADTBundle\sdk\tools\emulator -avd <name> -partition-size 512 -noaudio -no-snapshot -sdcard <avd image name>
    ## F:\School\Tools\ADTBundle\sdk\tools\emulator -avd newAVD -partition-size 512 -noaudio -no-snapshot -sdcard avdimage.img

    print()
    print("\t[+] Starting Emulator ")
    startcmd = andsdktoolpath + "\\emulator-x86.exe -avd " + avdname + " -partition-size " + partsize + " -noaudio "
    startcmd += "-no-snapshot -sdcard " + os.path.join(tempdir, sdname)

    if args.tcpdump:
        startcmd += " -tcpdump " + os.path.join(outpath, avdname) + "\\netdump.pcap"

    if args.proxy:
        startcmd += " -http-proxy " + args.proxy

    if verbose > 1:
        print("\t\tStart AVD command: " + startcmd)

    #Start the Process, then capture the PID
    avdproc = subprocess.Popen(startcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    avdpid = str(avdproc.pid)
    print("\t\tEmulator PID: " + avdpid)

    #Sleep until the device shows up in the adb devices list and is online
    devcount = listdevices(andplatformtools, verbose, count=True)
    retries = 1
    while devcount < 1 and retries < 6:
        time.sleep(10)
        devcount = listdevices(andplatformtools, verbose, count=True)
        if devcount == 0:
            print("\t\tWaiting on emulator...")
        elif devcount > 0:
            list = listdevices(andplatformtools, verbose)
            if 'offline' in list[0]:  #if the device is found but still offline, reset devcount to 0 to retry
                print('\t\tEmulator started but not online. Waiting...')
                print()
                devcount = 0
            else:
                print("\t\tEmulator ready.")
        retries += 1

    if retries == 6: #if the device doesn't show up in the list afte 60 seconds (5 retries) then exit
        print("Unable to locate the emulator using \"adb devices -l\". Exiting...")
        killavd(avdpid, avdname, sdname, tempdir, andsdktoolpath, verbose)
        sys.exit(1)

    print()
    print("[+] Preparing Emulator For Testing")

    #Remount emulator file system
    print()
    print("\t[+] Remounting Filesystem to Read/Write")

    remountcmd = andplatformtools + "\\adb shell mount -o rw,remount -t yaffs2 /dev/block/mtdblock0 /system"
    if verbose > 1:
        print("\t\tRemount Command: " + remountcmd)

    subprocess.call(remountcmd, shell=False)

    # Push busybox
    ## make directory /system/vendor/bin
    print()
    print("\t[+] Pushing Busybox")

    mkdircmd = andplatformtools + "\\adb shell mkdir -p /system/vendor/bin"
    subprocess.call(mkdircmd, shell=False)

    pushcmd = andplatformtools + "\\adb push " + busybox + " /system/vendor/bin"

    if verbose > 1:
        print("\t\tPush busybox command: " + pushcmd)

    subprocess.call(pushcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    #set busybox with +x
    subprocess.call(andplatformtools + "\\adb shell chmod 755 /system/vendor/bin/busybox-i686")

    if not args.manual:

        print()
        print("[+] Preparing App For Launch")
        time.sleep(2)

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

        decodedapk = decodeapk(args.apk, avdname, verbose)

        package, mainact = mi.printmainintent(decodedapk)
        mainintent = package + "/" + mainact
        print("\t\tPackage: " + package)
        print("\t\tMain Activity: " + mainact)

        ## Hash APK file before installing
        prehash = md5sum(args.apk)

        #Install the APK.
        installapk(andplatformtools, args.apk, verbose)

        #Find the installed apk on the device in the /data/app directory
        installpath = getinstallpath(andplatformtools, package, verbose)

        #Hash the installed APK file on the device
        hashcmd = andplatformtools + "\\adb shell md5 " + installpath

        hashoutput = subprocess.Popen(hashcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        posthash = hashoutput.stdout.readlines()[0].decode("ASCII").rstrip()

        print("\t\tPre-Install MD5:  " + prehash + " " + args.apk)
        print("\t\tPost-Install MD5: " + posthash.split()[0] + " " + posthash.split()[1])


        print()
        print("\t[+] Launching App")
        print("\t\tMain Intent: " + mainintent)
        launchcmd = andplatformtools + "\\adb shell am start -a android.intent.action.MAIN -n " + mainintent

        if verbose > 1:
            print("\t\tLaunch command: " + launchcmd)

        subprocess.Popen(launchcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        #Set marker to indicate beginning of app test
        setstartmarker(andplatformtools, verbose)

        #Sleep for a period of time (runtime) while app is running
        print("\t\tRunning App for " + str(runtime) + " Seconds")
        time.sleep(runtime)

        print()
        print("[+] Run time expired. Searching for touched files...")
        #get list of files touched since the start marker was set
        filelist = gettouchedfiles(andplatformtools, verbose)

        print()
        print("\tFound Files: ")
        if 'error: protocol fault (no status)' in filelist:
            print("\t\tNone...")
        else:
            for file in filelist:
                print("\t\t" + file)


        if 'error: protocol fault (no status)' not in filelist:
            print()
            print("\t[+] Pulling and hashing files")
            processfiles(filelist, andplatformtools, avdname, verbose)

        print()
        print("[+] Processing completed.")


        killavd(avdpid, avdname, sdname, tempdir, andsdktoolpath, verbose)

        print()
        print("[+] App Test Complete.")

    else: #if user specified the -m flag for manual control of the emulator
        print()
        print("[+] Emulator start up complete.")
        stopavd = False
        while not stopavd:
            print()
            stopavd = query_yes_no("Type 'yes' when you are done.\n\t\tAre you ready to kill the emulator?", "no")

        killavd(avdpid, avdname, sdname, tempdir, andsdktoolpath, verbose)





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
    parser_testavd.add_argument('--proxy', help="Enable TCP Proxy at the specified IP:Port", metavar="IP:PORT", required=False)
    parser_testavd.add_argument('--tcpdump', help="Dump network traffic to pcap file", action='store_true', required=False)
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