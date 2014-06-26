# Copied and mofified from --> http://www.bulbsecurity.com/backdooring-apks-programmatically-2/
import argparse
import sys
import datetime
import xml.etree.ElementTree as ET


def printmainintent(foldername):
    ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
    tree = ET.ElementTree()
    tree.parse(foldername + "/AndroidManifest.xml")
    root = tree.getroot()
    package = root.get('package')

    for child in root:
        if child.tag == "application":
            app = child
            for child in app:
                if child.tag == "activity":
                    act = child
                    for child in act:
                        if child.tag == "intent-filter":
                            filter = child
                            for child in filter:
                                if (filter[0].get(
                                        '{http://schemas.android.com/apk/res/android}name') == "android.intent.category.LAUNCHER" or
                                            filter[0].get(
                                                    '{http://schemas.android.com/apk/res/android}name') == "android.intent.action.MAIN"):
                                    if (filter[1].get(
                                            '{http://schemas.android.com/apk/res/android}name') == "android.intent.category.LAUNCHER" or
                                                filter[1].get(
                                                        '{http://schemas.android.com/apk/res/android}name') == "android.intent.action.MAIN"):
                                        mainact = act.get('{http://schemas.android.com/apk/res/android}name')
                                        if mainact[0] == ".":
                                            mainact = package + mainact
                                        break
    return package, mainact


def Header():
    print('')
    print('+--------------------------------------------------------------------------+')
    print('|Main Intent from AndroidManifest.XML                                      |')
    print('+---------------------------------------------------------------------------')
    print('|Author: Tahir Khan - tkhan9@gmu.edu                                       |')
    print('|Code borrowed from - http://www.bulbsecurity.com                          |')
    print('+--------------------------------------------------------------------------+')
    print('  Date Run: ' + str(datetime.datetime.now()))
    print('+--------------------------------------------------------------------------+')


def Completed():
    print('| [*] Completed.                                                           |')
    print('+--------------------------------------------------------------------------+')


def main(argv):
    global debug
    parser = argparse.ArgumentParser(description="A program to find the main intent of an APK.",
                                     add_help=True)
    parser.add_argument('-i', '--input', help='The input path where the AndroidManifest.XML file exists.',
                        required=True)
    parser.add_argument('-d', '--debug', help='The level of debugging.', required=False)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    if args.input:
        inputfile = args.input
    package, mainintent = printmainintent(inputfile)
    Header()
    print('| Package Name:\t' + package.ljust(59, ' ') + '|')
    print('| Main Intent:\t' + mainintent.ljust(59, ' ') + '|')
    Completed()


if __name__ == '__main__':
    main(sys.argv[1:])