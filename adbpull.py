__author__ = 'Liteman'


import hashlib 		#This imports the hashing functions
import argparse     #http://docs.python.org/3.4/library/argparse.html
import sys

def md5(file):
    #define blocksize for reading file
    block = 65536
    #open the file
    f = open(file, 'rb')
    #read in a buffer of size block
    buf = f.read(block)
    #calculate hash
    hash = hashlib.md5()
    #while file has more bytes, update the hash
    while len(buf) > 0:
        hash.update(buf)
        buf = f.read(block)
    return hash

def sha(file):
    #define blocksize for reading file
    block = 65536
    #open the file
    f = open(file, 'rb')
    #read in a buffer of size block
    buf = f.read(block)
    #calculate hash
    hash = hashlib.sha1()
    #while file has more bytes, update the hash
    while len(buf) > 0:
        hash.update(buf)
        buf = f.read(block)
    return hash

def main(argv):
    parser = argparse.ArgumentParser(description="MD5 Hash File", add_help=True)
    parser.add_argument('-f', '--file', help='The file to be hashed.', required=False)
    parser.add_argument('-s', '--sha1', help='Display SHA1 Hash as well', action='store_true')
    parser.add_argument('--version', action='version', version='%(prog)s 0.5')

    args = parser.parse_args()
    if args.file:
        file = args.file
        print ('MD5 Hash: ' + str(md5(file).hexdigest()))
        print ('MD5 Hash - Upper: ' + str(md5(file).hexdigest()).upper())
        #print (md5(file).hexdigest())
        if args.sha1:
            print ('SHA1 Hash: ' + str(sha(file).hexdigest()))
            print ('SHA1 Hash - Upper: ' + str(sha(file).hexdigest()).upper())



main(sys.argv[1:])