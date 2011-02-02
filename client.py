from optparse import OptionParser
import hashlib
import json
import os
import shutil
import stat
import sys

from OpenSSL.SSL import Context, VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from twisted.python.urlpath import URLPath
from twisted.internet.ssl import ContextFactory
from twisted.internet.error import ConnectionRefusedError
from twisted.internet import reactor, ssl
from twisted.web.client import getPage

class HTTPSVerifyingContextFactory(ContextFactory):
    isClient = True

    def __init__(self, hostname):
        self.hostname = hostname

    def getContext(self):
        contextFactory = ssl.DefaultOpenSSLContextFactory(
            '/home/andrew/tmp/syncfg/keys/client.key', '/home/andrew/tmp/syncfg/keys/client.crt'
            )
        ctx = contextFactory.getContext()
        ctx.load_verify_locations("/home/andrew/tmp/syncfg/keys/ca.crt")
        ctx.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT, self.verifyHostname)
        return ctx

    def verifyHostname(self, connection, x509, errno, depth, preverifyOK):
        if preverifyOK:
            if self.hostname == x509.get_subject().commonName:
                return False
        return preverifyOK

class Retriever:
    def __init__(self):
        self.reqs = 0
        self.ret_code = 0

    def get(self, url):
        httpsctx = HTTPSVerifyingContextFactory(URLPath(url).netloc)
        return getPage(url, httpsctx)

    def process_response(self, resp):
        if resp['status'] != "outdated":
            return

        if not ('filename' in resp and 'new_file' in resp and 'latest_hash' in resp):
            print >> sys.stderr, "error: received malformed response from server:",resp
            exit(2)

        stagefile = os.path.join(STAGING_DIR, resp['filename'])
        stagedir = os.path.dirname(stagefile)
        if not os.path.exists(stagedir):
            os.makedirs(stagedir)

        try:
            f = open(stagefile ,'w')
            f.write(resp['new_file'].encode("utf-8"))
            f.close()
        except IOError, e:
            print >> sys.stderr, "error writing staging file:", e
            return

        if self.hash(stagefile) != resp['latest_hash']:
            print >> sys.stderr, "error: written file's hash does not match hash received"
            return

        newfile = os.path.join(HOMEDIR, resp['filename'])
        
        try:
            if os.path.exists(newfile):
                oldfile = os.path.join(BACKUP_DIR, resp['filename']+"_"+self.hash(newfile))
                olddir = os.path.dirname(oldfile)
                if not os.path.exists(olddir):
                    os.makedirs(olddir)

                shutil.copy2(newfile, oldfile)
        except IOError, e:
            print >> sys.stderr, "error backing up old file:", e
            return
    
        try:
            os.chmod(stagefile, int(resp["permissions"]))
            shutil.move(stagefile, newfile)
        except IOError, e:
            print >> sys.stderr, "error mving new config over old one:", e
            return

    def add_file(self, url):
        req=self.get(url)
        req.addCallback(self.done_file)
        req.addErrback(self.error)
        self.reqs += 1

    def add_dir(self, url):
        req=self.get(url)
        req.addCallback(self.done_dir)
        req.addErrback(self.error)
        self.reqs += 1
                        
    def done_dir(self, result):
        self.reqs -= 1

        responses = json.loads(result)
        for resp in responses:
            for dir in resp['dirs']:
                indir = os.path.join(HOMEDIR,dir)
                if not os.path.exists(indir):
                    os.mkdir(indir)
                elif not os.path.isdir(indir):
                    print >> sys.stderr, "error: requested dir already exists but is not a directory:",indir
                    exit(1)

            for file in resp['files']:
                file = str(file)
                csum = self.hash(os.path.join(HOMEDIR,file))
                self.add_file("https://%s?file=%s&hash=%s" % (SERVER, file, csum))

        self.stop_if_done()

    def done_file(self, result):
        self.reqs -= 1
        responses = json.loads(result)
        for resp in responses:
            self.process_response(resp)
        self.stop_if_done()

    def error(self, error):
        self.reqs -= 1
        print >> sys.stderr, 'error making SSL request:',error.getErrorMessage()
        self.ret_code = 3
        self.stop_if_done()

    def stop_if_done(self):
        if self.reqs < 1:
            reactor.stop()
                
    def hash(self, filename):
        if not os.path.exists(filename):
            return -1

        input = ""
        try:
            f = open(filename)
            input = f.read()
            f.close()
        except IOError, e:
            print >> sys.stderr, "error hashing file:",e
            exit(1)
        sha = hashlib.sha512()
        sha.update(input)
        return sha.hexdigest()
        
def file_cb(option, opt, value, parser):
    fileargs.append(value)

def dir_cb(option, opt, value, parser):
    dirargs.append(value)

def main(infiles, indirs):
    files = []
    csums = []
    walker = Walker()
        
    # check file args
    for infile in infiles:
        files.append(infile)

        retriever = Retriever()
        if os.path.exists(infile):
            csums.append(retriever.hash(infile))
        else:
            csums.append(0)

    for indir in indirs:
        retriever.add_dir("https://%s?dir=%s" % (SERVER, indir))

    for file,csum in zip(files,csums):
        sanefile = file.replace(HOMEDIR,"")
        retriever.add_file("https://%s?file=%s&hash=%s" % (SERVER, sanefile, csum))
        #get=retriever.get("https://%s?file=%s&hash=%s" % (SERVER, sanefile, csum))
        #get.addCallback(retriever.done)
        #get.addErrback(retriever.error)
    
    reactor.run()
    exit(retriever.ret_code)

class Walker:
    def walk_dir(self, dirout, dirname, names):
        for filename in names:
            path = os.path.join(dirname, filename)
            if not os.path.isdir(path):
                dirout.append(path)

STAGING_DIR = os.path.expanduser("~/tmp/syncfg/stage/")
BACKUP_DIR = os.path.expanduser("~/tmp/syncfg/backup/")
#HOMEDIR = os.path.expanduser("~/")
HOMEDIR = os.path.expanduser("~/tmp/syncfg/home/")
SERVER = "samizdat.odos.me:7080"

fileargs = []
dirargs = []
parser = OptionParser()
parser.add_option("-f", "--file", action="callback", help="write report to FILE", callback=file_cb, type="string")
parser.add_option("-d", "--dir", action="callback", help="write report to FILE", callback=dir_cb, type="string")

os.umask(077)

(options, args) = parser.parse_args()
main(fileargs, dirargs)
