__author__ = 'Liteman'
''' This tool requires the Android SDK - specifically adb.exe
'''

import subprocess
import hashlib


pathToADB = "F:\\School\\Tools\\adt-bundle-windows-x86_64-20140321\\adt-bundle-windows-x86_64-20140321\\sdk\\platform-tools"
saveLocation = "C:\\users\\liteman\\desktop"

apps = []
localhashlist = {}
remotehashlist = {}

#Get list of APKs on device
listAPKs = subprocess.Popen(pathToADB + "\\adb.exe shell ls /data/app", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

#Refine list into manageable, distinct strings
for apk in listAPKs.stdout.readlines():
   apps.append(apk.decode("ASCII").rstrip())


#Print Remote Hashes
for apk in apps:
    cmd = subprocess.Popen(pathToADB + "\\adb.exe shell md5 /data/app/" + apk, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    remotehashlist[apk] = cmd.stdout.readline().split()[0].decode("ASCII").rstrip()

#Pull and Hash APKs
for apk in apps:
    subprocess.call(pathToADB + "\\adb.exe pull /data/app/" + apk + " " + saveLocation, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    f = open(saveLocation + "\\" + apk, 'rb')
    block = 65536
    #read in a buffer of size block
    buf = f.read(block)
    #calculate hash
    hash = hashlib.md5()
    #while file has more bytes, update the hash
    while len(buf) > 0:
        hash.update(buf)
        buf = f.read(block)
    localhashlist[apk] = str(hash.hexdigest())
    f.close()

match = "Not Set"
for keyLocal, valueLocal in localhashlist.items():
    if (remotehashlist.get(keyLocal)):
        if(valueLocal == remotehashlist[keyLocal]):
            match = "Match"
            print(match + "\t" + valueLocal + "\t" + remotehashlist[keyLocal] + "\t" + keyLocal)
        else:
            match = "Not Match"
            print(match + "\t" + valueLocal + "\t" + remotehashlist[keyLocal] + "\t" + keyLocal)
    else:
        print("Error -- Local file: " + keyLocal + " was not found in the remote list")









