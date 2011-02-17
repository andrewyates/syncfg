import hashlib
import json
import os
import stat
import sys
import time

from OpenSSL import SSL
from pylibconfig import Config
from twisted.internet import reactor, ssl
from twisted.web.resource import Resource
from twisted.web import server
from sqlalchemy.orm import sessionmaker

from sql import *

class ConfigPage(Resource):
    """ Responds to file and directory requests """
    isLeaf = True

    def render_GET(self, request):
        """ Determine whether the request was for a file or directory and handle it. Called on every request. """
        print "request:",request
        if "dir" in request.args: # dir request?
            return self.respond_dir(request)
        elif "file" in request.args: # config request?
            return self.respond_file(request)
        else: # unknown request
            return "error: received invalid GET string"

    def respond_dir(self, request):
        """ Respond to a directory request """
        dirs = []
        for k,v in request.args.items():
            if isinstance(v, list):
                for elt in v: dirs.append(elt)
            else:
                dirs.append(v)

        host = request.channel.transport.getPeerCertificate().get_subject().commonName
        out = []
        for dir in dirs:
            out.extend(self.get_dir_info(dir, host))

        return json.dumps(out, sort_keys=False, indent=4)

    def get_dir_info(self, dir, host):
        """ Prepare a directory response """
        out = []
        #TODO
        #for dir in get_dirs(host):
        Session = sessionmaker(bind=self.engine)
        session = Session()
        for res in (session.query(Dir, DirHost, Host)
                    .filter(Dir.id==DirHost.dir_id)
                    .filter(DirHost.host_id==Host.id)
                    .filter(Host.hostname == host)):
            dirout = {}
            out.append(dirout)
            dirout["dir"] = res[0].dir
            dirout["dirs"] = []
            dirout["files"] = []
            os.path.walk(os.path.join(self.DIR_DIR,dirout["dir"]), self.walk_dir, dirout);
                
        return out

    def walk_dir(self, dirout, dirname, names):
        """ Walk a directory tree and keep track of the files inside """
        basedir = dirname.replace(self.DIR_DIR,"")
        dirout["dirs"].append(basedir)
        for filename in names:
            path = os.path.join(dirname,str(filename))
            if not os.path.isdir(path):
                dirout["files"].append(os.path.join(basedir,str(filename)))

    def respond_file(self, request):
        """ Respond to a file request """
        files = []
        hashes = []

        for k,v in request.args.items():
            if isinstance(v, list):
                for elt in v:
                    self.add_file(files, hashes, k, elt)
            else:
                self.add_file(files, hashes, k, v)

        if len(files) != len(hashes):
            raise ValueError("file/hash count mismatch")

        host = request.channel.transport.getPeerCertificate().get_subject().commonName

        out = []
        for file,hash in zip(files,hashes):
            out.append(self.check_file(file,hash,host))
        
        return json.dumps(out, sort_keys=False, indent=4)

    def check_file(self, file, hash, host):
        """ Check whether the remote file is up to date and return an appropriate response """
        out = {}
        out['filename'] = file
        out['your_hash'] = hash
        out['latest_hash'] = self.get_latest_hash(file, host)
        if out['your_hash'] == out['latest_hash']: 
            out['status'] = "ok" 
        elif out['latest_hash'] == "":
            out['status'] = "missing"
        else:
            out['status'] = "outdated"
            out['new_file'], out['permissions'] = self.get_file(file, host)
        return out

    def get_file(self, file, host):
        """ Find file and return a (file, permissions) pair """
        out = ""
        found = False
        perm = None
        #TODO
        #for cfg in get_configs(file, host)
        Session = sessionmaker(bind=self.engine)
        session = Session()
        for cfg in (session.query(Config,ConfigPart,Host)
                    .filter(Config.id==ConfigPart.config_id)
                    .filter(Config.host_id==Host.id)
                    .filter(Config.file == file)
                    .filter(Host.hostname == host)
                    .order_by(ConfigPart.rank)):
            try:
                filepath = os.path.join(self.CONFIG_DIR,cfg[1].file)
                f = open(filepath)
                out += f.read()
                f.close()
                thisperm = stat.S_IMODE(os.stat(filepath).st_mode)
                if perm is None or thisperm < perm:
                    perm = thisperm
                found = True
            except IOError, e:
                print >> sys.stderr, "IOError opening file from DB:",e

        # if file not found, check static dirs for it
        # TODO add check so this doesn't return files not actually in static dirs
        if found:
            return (out, perm)
        else:
            try:
                filepath = os.path.join(self.DIR_DIR,file)
                f = open(filepath)
                out += f.read()
                f.close()
                perm = stat.S_IMODE(os.stat(filepath).st_mode)
                return (out, perm)
            except IOError, e:
                print >> sys.stderr, "IOError opening file from DB:",e

        return (None, None)

    def get_latest_hash(self, file, host):
        """ Calculate file's latest hash """
        text, perms = self.get_file(file, host)
        if text != None:
            sha = hashlib.sha512()
            sha.update(text)
            return sha.hexdigest()
        else:
            return ""

    def add_file(self, files, hashes, key, val):
        if key == "hash":
            hashes.append(val)
        elif key == "file":
            files.append(val)
        else:
            raise ValueError("unknown key: %s" % key)

    # Note: on connection this is called first once with CA cert and again with client cert
    def verifyCallback(self, connection, x509, errnum, errdepth, ok):
        """ Determine whether the SSL connection should be allowed """
        if not ok:
            print 'info: invalid cert received:', x509.get_subject()
            return False

        #TODO
        #if fingerprint_valid(host, fingerprint):
        Session = sessionmaker(bind=self.engine)
        session = Session()
        query = (session.query(Host)
                 .filter(Host.hostname == x509.get_subject().commonName)
                 .filter(Host.fingerprint == x509.digest("sha512")))
        if query.first():
            return True
        else:
            # unknown host
            print 'warning: denying connection from a cert that validates but does not exist in the config:', x509.get_subject(), x509.digest("sha512")
            return False

def prepare_server(basedir):
    """ Prepare a ConfigPage object with reasonable defaults and return a (port, Resource, ContextFactory) tuple """
    r = ConfigPage()
    r.BASE_DIR = basedir + os.path.sep
    r.CONFIG_DIR = os.path.join(r.BASE_DIR, "configs") + os.path.sep
    r.DIR_DIR = os.path.join(r.BASE_DIR, "dirs") + os.path.sep
    r.PRIVKEY = os.path.join(r.BASE_DIR,'keys/server.key')
    r.PUBKEY = os.path.join(r.BASE_DIR, 'keys/server.crt')
    r.CA_PUBKEY = os.path.join(r.BASE_DIR,"keys/ca.crt")
    r.DB_URL = "sqlite:///"+ r.BASE_DIR + "sqlite"
    r.engine = init_engine(r.DB_URL)


    contextFactory = ssl.DefaultOpenSSLContextFactory(r.PRIVKEY, r.PUBKEY)
    ctx = contextFactory.getContext()
    ctx.set_verify(
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
        r.verifyCallback
        )
    ctx.load_verify_locations(r.CA_PUBKEY)

    return (7080, r, contextFactory)

engine = None

def main():
    if len(sys.argv) != 2:
        print >> sys.stderr, "usage: %s <base directory>" % sys.argv[0]
        exit(3)

    basedir = sys.argv[1]
    if not os.path.isdir(basedir):
        print >> sys.stderr, "error: base directory '%s' does not exist" % basedir
        exit(4)

    config = Config()
    config.readFile("config")
    print config
    exit(1)

    port, configPage, contextFactory = prepare_server(basedir)
    site = server.Site(configPage)
    reactor.listenSSL(port, site, contextFactory)
    reactor.run()

if __name__ == '__main__':
    main()
