__author__ = 'Liteman'
import sys
import subprocess


pathUnpacked = "F:\\School\\780-MobileApps\\apks_unpacked"



def main(argv):
    pathToAPKs = "F:\\School\\780-MobileApps\\"
    sevZcmd = '\"C:\\Program Files\\7-Zip\\7z\"'

    apks = []
    apklist = subprocess.Popen("forfiles /P " + pathToAPKs + " /M *.apk", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for apk in apklist.stdout:
        apks.append(apk.decode("ASCII").rstrip()[1:-1])


    #unpack apks
    for apk in apks[1:]:
        #debug: print(sevZcmd + " x " + pathToAPKs + apk + " -o"+pathUnpacked + "\\"+apk[:-4])
        subprocess.Popen(sevZcmd + " x " + pathToAPKs +  apk + " -o"+pathUnpacked + "\\"+apk[:-4], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)







main(sys.argv[1:])
