import hashlib
import json
import os
import stat
import sys
import time

from OpenSSL import SSL
import pylibconfig 
from twisted.internet import reactor, ssl
from twisted.web.resource import Resource
from twisted.web import server
#from sqlalchemy.orm import sessionmaker

#from sql import *

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

        host = self.config_fqdn_to_name(request.channel.transport.getPeerCertificate().get_subject().commonName)
        out = []
        for dir in dirs:
            out.extend(self.get_dir_info(dir, host))

        return json.dumps(out, sort_keys=False, indent=4)

    def config_get_dirs(self, host):
        if host in self.host2dir:
            return self.host2dir[host]

        dirs = []
        key = host + ".dirs"
        for dirkey in self.config.children(key):
            dir, valid = self.config.value(dirkey)
            if valid: dirs.append(dir)
        
        self.host2dir[host] = dirs
        return dirs

    def config_load(self):
        """ Loads the config file """
        self.config_reload()

    def config_reload(self):
        """ Reloads the config file and clears all cached values """
        self.config = pylibconfig.Config()
        self.config.readFile(self.CONFIG_FILE)
        self.fqdn2name = {}   # caches FQDN to host name mappings
        self.host2config = {} # caches (host name, config name) to config files mappings
        self.host2dir = {}    # caches host name to static directory list mappings

        # map shared hosts to lists of their configs
        shost2configs = {}
        shared_hosts, normal_hosts = self.config_shared_hosts()
        sh_set = set(shared_hosts)
        for host in shared_hosts:
            configs = []
            shost2configs[host] = configs
            for cfgkey in self.config.children(host+".configs"):
                configs.append(self.config_parse_config_block(cfgkey))
                
        # add configs from inherited hosts to the cache
        for host in normal_hosts: # check each host for an inherit statement
            inherit, valid = self.config.value(host+".inherit")
            if not valid:
                continue
            if not inherit in sh_set:
                print >> sys.stderr, ("warning: host wants to %s inherit from %s, but %s is not a shared host" 
                                      % (host, inherit, inherit))
                continue
            
            # add all the shared host's configs to the current host
            for name,sources in shost2configs[inherit]:
                key = (host, name)
                if key in self.host2config:
                    print >> sys.stderr, "error: config %s for host %s inherited more than once" % (name,host)
                    continue
                self.host2config[key] = sources
                
    def config_shared_hosts(self):
        """ Return a (shared_hosts, normal_hosts) tuple consisting of:
            1) A list of hosts that may be inherited from. These are hosts with only a "configs" section. 
            2) The other hosts. """
        shared_hosts = []
        normal_hosts = []
        for host in self.config.children():
            children = self.config.children(host)
            if len(children) == 1 and children[0] == host+".configs":
                shared_hosts.append(host)
            else:
                normal_hosts.append(host)

        return (shared_hosts, normal_hosts)

    def get_dir_info(self, dir, host):
        """ Prepare a directory response """
        out = []
        for dir in self.config_get_dirs(host):
        #for res in (session.query(Dir, DirHost, Host)
        #            .filter(Dir.id==DirHost.dir_id)
        #            .filter(DirHost.host_id==Host.id)
        #            .filter(Host.hostname == host)):
            dirout = {}
            out.append(dirout)
            dirout["dir"] = dir
            #dirout["dir"] = res[0].dir
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

        host = self.config_fqdn_to_name(request.channel.transport.getPeerCertificate().get_subject().commonName)

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

    def config_parse_config_block(self, cfgkey):
        """ Parses a config file block and returns a (file name, file source list) pair """
        files = []
        namekey = cfgkey+ '.name'
        srckey = cfgkey+ '.source'
        name, nameValid = self.config.value(namekey)
        if not nameValid:
            print >> sys.stderr, "error: config block missing name key: ",namekey
            return None
        for srcfilekey in self.config.children(srckey):
            filename, valid = self.config.value(srcfilekey)
            if not valid:
                print >> sys.stderr, "error: error in config block with key: ",srcfilekey
                return None
            files.append(filename)

        return (name, files)

    def config_get_configs(self, file, host):
        key = (host, file)
        if key in self.host2config:
            return self.host2config[key]

        files = []
        key = host + '.configs'
        for cfgkey in self.config.children(key):
            (name, n_files) = self.config_parse_config_block(cfgkey)
            if name == file:
                files = n_files

        self.host2config[key] = files # cache list of file's sources
        return files

    def get_file(self, file, host):
        """ Find file and return a (file, permissions) pair """
        out = ""
        found = False
        perm = None
        for cfg in self.config_get_configs(file, host):
        #Session = sessionmaker(bind=self.engine)
        #session = Session()
        #for cfg in (session.query(Config,ConfigPart,Host)
        #            .filter(Config.id==ConfigPart.config_id)
        #            .filter(Config.host_id==Host.id)
        #            .filter(Config.file == file)
        #            .filter(Host.hostname == host)
        #            .order_by(ConfigPart.rank)):
            try:
                #filepath = os.path.join(self.CONFIG_DIR,cfg[1].file)
                filepath = os.path.join(self.CONFIG_DIR,cfg)
                f = open(filepath)
                out += f.read()
                f.close()
                thisperm = stat.S_IMODE(os.stat(filepath).st_mode)
                if perm is None or thisperm < perm:
                    perm = thisperm
                found = True
            except IOError, e:
                print >> sys.stderr, "IOError opening file:",e

        # if file not found, check static dirs for it
        # TODO add check so this doesn't return files not actually in static dirs
        if found:
            return (out, perm)
        else:
            dirs = self.config_get_dirs(host)
            inStaticDir = False
            for dir in dirs:
                if file.find(dir) == 0:
                    inStaticDir = True
                    break

            if inStaticDir:
                try:
                    filepath = os.path.join(self.DIR_DIR,file)
                    f = open(filepath)
                    out += f.read()
                    f.close()
                    perm = stat.S_IMODE(os.stat(filepath).st_mode)
                    return (out, perm)
                except IOError, e:
                    print >> sys.stderr, "IOError opening file:",e

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

    def config_fqdn_to_name(self, host):
        if host in self.fqdn2name:
            return self.fqdn2name[host]

        for hostkey in self.config.children():
            fqdnkey = hostkey+".fqdn"
            fqdn, valid = self.config.value(fqdnkey)
            if valid and fqdn == host:
                self.fqdn2name[host] = hostkey
                return hostkey
        return None
            

    def config_fingerprint_valid(self, host, fingerprint):
        CA, valid = self.config.value("CA")
        CAfp, fpValid = self.config.value("CA_fingerprint")
        if not valid or not fpValid:
            return False

        # check the CA's fingerprint seperately from the other hosts
        if len(CA) > 1 and CA == host and CAfp == fingerprint:
            return True

        host = self.config_fqdn_to_name(host)

        fpkey = host + ".fingerprint"
        config_fp, valid = self.config.value(fpkey)
        if not valid:
            return False
        else:
            return config_fp == fingerprint

    # Note: on connection this is called first once with CA cert and again with client cert
    def verifyCallback(self, connection, x509, errnum, errdepth, ok):
        """ Determine whether the SSL connection should be allowed """
        if not ok:
            print 'info: invalid cert received:', x509.get_subject()
            return False

        if self.config_fingerprint_valid(x509.get_subject().commonName, x509.digest("sha512")):
        #Session = sessionmaker(bind=self.engine)
        #session = Session()
        #query = (session.query(Host)
        #         .filter(Host.hostname == x509.get_subject().commonName)
        #         .filter(Host.fingerprint == x509.digest("sha512")))
        #if query.first():
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
    r.CONFIG_FILE = os.path.join(r.BASE_DIR, "config")

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

    port, configPage, contextFactory = prepare_server(basedir)
    configPage.config_load()

    site = server.Site(configPage)
    reactor.listenSSL(port, site, contextFactory)
    reactor.run()

if __name__ == '__main__':
    main()
