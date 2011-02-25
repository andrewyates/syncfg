# This file is a part of syncfg, a system for synchronizing config files and supporting directories.
# Copyright (C) 2011 by Andrew Yates <andrew.yates@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.
#

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from optparse import OptionParser

import pylibconfig
from OpenSSL.SSL import Context, VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from twisted.python.urlpath import URLPath
from twisted.internet.ssl import ContextFactory
from twisted.internet.error import ConnectionRefusedError
from twisted.internet import reactor, ssl
from twisted.web.client import getPage

class HTTPSVerifyingContextFactory(ContextFactory):
    """ ContextFactory for connecting to syncfgd with HTTPS and a client key """
    isClient = True

    def __init__(self, hostname):
        self.hostname = hostname

    def getContext(self):
        contextFactory = ssl.DefaultOpenSSLContextFactory(
            config['private_key'], config['public_key']
            )
        ctx = contextFactory.getContext()
        ctx.load_verify_locations(config['ca_key'])
        ctx.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT, self.verifyHostname)
        return ctx

    def verifyHostname(self, connection, x509, errno, depth, preverifyOK):
        return preverifyOK

class Retriever:
    """ Requests and retrieves files and directories from the config server """
    def __init__(self):
        self.reqs = 0
        self.ret_code = 0

    def get(self, url):
        """ Retrieve a URL """
        httpsctx = HTTPSVerifyingContextFactory(URLPath(url).netloc)
        return getPage(url, httpsctx)

    def process_response(self, resp):
        """ Process the server's response to a file request, updating the current file if it is oudated """


        if not ('filename' in resp and 'status' in resp):
            print >> sys.stderr, "error: received malformed response from server:",resp
            exit(2)

        if resp['status'] != "outdated":
            if VERBOSE: print "%s: %s" % (resp['filename'], resp['status'])
            return

        if not ('new_file' in resp and 'latest_hash' in resp):
            print >> sys.stderr, "error: received malformed response from server:",resp
            exit(2)

        stagefile = os.path.join(STAGING_DIR, resp['filename'])
        stagedir = os.path.dirname(stagefile)
        if not os.path.exists(stagedir):
            os.makedirs(stagedir)

        if not os.path.exists(HOOK_DIR):
            os.makedirs(HOOK_DIR)

        sanefn = resp['filename'].replace("/","-")
            
        # write any hooks the file may have
        for hook in ['prehook', 'posthook']:
            if hook in resp and resp['prehook'] != "":
                try:
                    name = hook+"_"+sanefn
                    hookfile = os.path.join(HOOK_DIR, name)
                    f = open(hookfile, 'w')
                    f.write(base64.b64decode(resp[hook].encode("utf-8")))
                    f.close()
                    # chmod hook 750 (int 488)
                    os.chmod(hookfile, 488)
                except IOError, e:
                    print >> sys.stderr, "error writing hook file:", e
                    return

        # run prehook if it exists
        if 'prehook' in resp and resp['prehook'] != "":
            subprocess.call([os.path.join(HOOK_DIR, "prehook_"+sanefn)])

        try:
            f = open(stagefile ,'w')
            f.write(base64.b64decode(resp['new_file'].encode("utf-8")))
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
            if VERBOSE: print "%s: updated" % resp['filename']
        except IOError, e:
            print >> sys.stderr, "error mving new config over old one:", e
            return

        # run posthook if it exists
        if 'posthook' in resp and resp['posthook'] != "":
            subprocess.call([os.path.join(HOOK_DIR, "posthook_"+sanefn)])


    def list(self, url):
        """ Retrieve a list of configs and files """
        req=self.get(url)
        req.addCallback(self.done_list)
        req.addErrback(self.error)
        self.reqs += 1

    def update(self, url):
        """ Update all managed configs and files """
        req=self.get(url)
        req.addCallback(self.done_updatelist)
        req.addErrback(self.error)
        self.reqs += 1

    def add_files(self, infiles):
        """ Adds a list of files to be retrieved """
        files = []
        csums = []
        # calculate hashes for any existing files
        for infile in infiles:
            files.append(infile)
            
            if os.path.exists(infile):
                csums.append(self.hash(infile))
            else:
                csums.append(0)

        # queue server requests for the requested files
        for file,csum in zip(files,csums):
            sanefile = file.replace(HOMEDIR,"")
            self.add_file("https://%s?file=%s&hash=%s" % (SERVER, sanefile, csum))


    def add_file(self, url):
        """ Add a file to be retrieved """
        req=self.get(url)
        req.addCallback(self.done_file)
        req.addErrback(self.error)
        self.reqs += 1

    def add_dirs(self, indirs):
        """ Add a list of directories to be retrieved """
        for indir in indirs:
            self.add_dir("https://%s?dir=%s" % (SERVER, indir))

    def add_dir(self, url):
        """ Add a directory to be retrieved """
        req=self.get(url)
        req.addCallback(self.done_dir)
        req.addErrback(self.error)
        self.reqs += 1
                        
    def done_dir(self, result):
        """ Receive and handle the server's response to a directory request """
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
        """ Receive and handle the server's response to a file request """
        self.reqs -= 1
        responses = json.loads(result)
        for resp in responses:
            self.process_response(resp)
        self.stop_if_done()

    def done_list(self, result):
        """ Receive list and print to stdout """
        self.reqs -= 1
        print result
        self.stop_if_done()

    def done_updatelist(self, result):
        """ Receive list and attempt to update each one """
        self.reqs -= 1

        files = []
        dirs = []

        responses = json.loads(result)
        for resp in responses:
            if 'configs' in resp:
                for config in resp["configs"]:
                    files.append(os.path.join(HOMEDIR,str(config)))
            elif 'dirs' in resp:
                for dir in resp["dirs"]:
                    dirs.append(os.path.join(HOMEDIR,str(dir)))

        self.add_dirs(dirs)
        self.add_files(files)

        self.stop_if_done()

    def error(self, error):
        """ Callback for errors encountered when communicating with the server """
        self.reqs -= 1
        print >> sys.stderr, 'error making SSL request:',error.getErrorMessage()
        self.ret_code = 3
        self.stop_if_done()

    def stop_if_done(self):
        """ Stop the reactor if all pending file and dir requests have been completed """
        if self.reqs < 1:
            reactor.stop()
                
    def hash(self, filename):
        """ Return filename's SHA-512 hexdigest or -1 if filename does not exist """
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

def main(infiles, indirs, options):
    retriever = Retriever()

    # list this host's configs and dirs?
    if options.listConfigs:
        retriever.list("https://%s?list=true" % SERVER)

    # update all configs?
    if options.updateAll:
        retriever.update("https://%s?list=true" % SERVER)
    else:
        # queue server requests for the requested directories
        retriever.add_dirs(indirs)
        
        # queue server requests for the requested files
        retriever.add_files(infiles)
    
    # fetch requested files and dirs
    reactor.run()
    exit(retriever.ret_code)

def parse_config_file(filename):
    """ Parse config file and return a dict of statements """
    config = {}
    cfg = pylibconfig.Config()
    cfg.readFile(filename)

    # valid config statements / keys
    for stmt in ['staging_dir', 'backup_dir', 'home_dir', 'hook_dir', 
                 'server', 'private_key', 'public_key', 'ca_key']:
        value, valid = cfg.value(stmt)
        if not valid:
            print >> sys.stderr, "error: config file missing '%s' statement" % stmt
            sys.exit(1)
        
        if value[-1] != os.path.sep and stmt[-4:len(stmt)] == "_dir": # make sure all paths end with a /
            value += os.path.sep
        
        config[stmt] = os.path.expanduser(value)

    return config

config = parse_config_file(os.path.expanduser("~/.config/syncfg/config"))
STAGING_DIR = config['staging_dir']
BACKUP_DIR = config['backup_dir']
HOMEDIR = config['home_dir']
HOOK_DIR = config['hook_dir']
SERVER = config['server']

fileargs = []
dirargs = []
parser = OptionParser()
parser.add_option("-f", "--file", action="callback", help="file to be synced", callback=file_cb, type="string")
parser.add_option("-d", "--dir", action="callback", help="directory to be synced", callback=dir_cb, type="string")
parser.add_option("-l", "--list",
                  action="store_true", dest="listConfigs", default=False,
                  help="print a JSON-formatted list of this host's configs and directories")
parser.add_option("-u", "--update-all",
                  action="store_true", dest="updateAll", default=False,
                  help="update all managed configs and directories")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="print information about configs and directories as they are updated")


# use a safe default umask
os.umask(077)

(options, args) = parser.parse_args()
VERBOSE = options.verbose
main(fileargs, dirargs, options)
