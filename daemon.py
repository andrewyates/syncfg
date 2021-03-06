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
import signal
import stat
import sys
import syslog
import time

from OpenSSL import SSL
from syslog import LOG_ERR, LOG_WARNING, LOG_INFO

import pylibconfig 
from twisted.internet import reactor, ssl
from twisted.web.resource import Resource
from twisted.web import server

class ConfigPage(Resource):
    """ Responds to file and directory requests """
    isLeaf = True

    def render_GET(self, request):
        """ Determine whether the request was for a file or directory and handle it. Called on every request. """
        self.log("request: %s" % request, LOG_INFO)
        if "dir" in request.args: # dir request?
            return self.respond_dir(request)
        elif "file" in request.args: # config request?
            return self.respond_file(request)
        elif "list" in request.args: # config&dir list request?
            return self.respond_list(request)
        else: # unknown request
            return "error: received invalid GET string"

    def respond_list(self, request):
        """ Respond to a request for a list of all managed configs and directories """

        host = self.config_fqdn_to_name(request.channel.transport.getPeerCertificate().get_subject().commonName)

        self.config_cache_configs(host)
        dirs = self.config_get_dirs(host)

        out = []
        cfgs = {"configs": self.host2config[host].keys()}
        dirs = {"dirs": dirs}
        out.extend([cfgs])
        out.extend([dirs])
        return json.dumps(out,sort_keys=False, indent=4)

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

    def log(self, msg, priority):
        if self.syslog and (self.log_info or priority != LOG_INFO):
            syslog.syslog(priority, msg)
        else:
            if priority == LOG_ERR:
                prefix = "error: "
                out = sys.stderr
            elif priority == LOG_WARNING:
                prefix = "warning: "
                out = sys.stderr
            elif priority == LOG_INFO:
                prefix = "info: "
                out = sys.stdout

            if self.log_info or priority != LOG_INFO:
                print >> out, prefix + msg

    def config_get_dirs(self, host):
        """ Returns a list of directories for host from the config file"""
        if host in self.host2dir: 
            return self.host2dir[host]

        dirs = []
        key = host + ".dirs"
        for dirkey in self.config.children(key):
            dir, valid = self.config.value(dirkey)
            if valid: dirs.append(dir)
        
        self.host2dir[host] = dirs

        self.config_cache_dirfiles(host)

        return dirs

    def config_load(self):
        """ Loads the config file """
        self.config_reload()

    def config_reload(self):
        """ Reloads the config file and clears all cached values """
        self.config = pylibconfig.Config()
        self.config.readFile(self.CONFIG_FILE)
        self.fqdn2name = {}   # caches FQDN to host name mappings
        self.host2config = {} # caches host name to config name to config files mappings (host -> name -> file list)
        self.host2dir = {}    # caches host name to static directory list mappings
        self.host2dirfiles = {} # caches host name to list of files in static directories mappings
        self.cached_host_configs = set([])
        self.cached_host_dirfiles = set([])

        # log to syslog?
        syslogValue, syslogValid = self.config.value("syslog")
        if syslogValid and syslogValue.lower() == "true":
            self.syslog = True
            syslog.openlog("syncfgd", syslog.LOG_PID, syslog.LOG_DAEMON)
        else:
            self.syslog = False

        # log info?
        info, infoValid = self.config.value("log_info")
        if infoValid and info.lower() == "true":
            self.log_info = True
        else:
            self.log_info = False

        self.log("loading config", LOG_INFO)

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
                self.log("host wants to %s inherit from %s, but %s is not a shared host" 
                                      % (host, inherit, inherit), LOG_WARNING)
                continue
            
            # add all the shared host's configs to the current host
            for name,sources,pre,post in shost2configs[inherit]:
                key = (host, name)
                if host in self.host2config and name in self.host2config[host]:
                    self.log("config %s for host %s inherited more than once" % (name,host), LOG_ERR)
                    continue
                if host not in self.host2config:
                    self.host2config[host] = {}
                self.host2config[host][name] = (sources,pre,post)
                
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
            dirout = {}
            out.append(dirout)
            dirout["dir"] = dir
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
        else:
            out['status'] = "outdated"
            contents, perms = self.get_file(file, host)
            out['new_file'], out['permissions'] = base64.b64encode(contents), perms
            if file in self.host2config[host]:
                sources, pre, post = self.host2config[host][file]
            elif file in self.host2dirfiles[host]:
                sources, pre, post = [file], "", ""
            else:
                sources, pre, post = ["UNKNOWN", "", ""]
                self.log("could not find requested file: %s" % file, LOG_WARNING)
            out['prehook'] = base64.b64encode(pre)
            out['posthook'] = base64.b64encode(post)
        return out

    def config_parse_config_block(self, cfgkey):
        """ Parses a config file block and returns a (file name, file source list, pre hook, post hook) tuple """
        files = []
        prehook, posthook = "", ""
        namekey = cfgkey+ '.name'
        srckey = cfgkey+ '.source'
        name, nameValid = self.config.value(namekey)
        if not nameValid:
            self.log("config block missing name key: %s" % namekey, LOG_ERR)
            return None
        for srcfilekey in self.config.children(srckey):
            filename, valid = self.config.value(srcfilekey)
            if not valid:
                self.log("error in config block with key: %s" % srcfilekey, LOG_ERR)
                return None
            files.append(filename)

        prehook, preValid = self.config.value(cfgkey+'.hook-client-pre-update-script')
        posthook, postValid = self.config.value(cfgkey+'.hook-client-post-update-script')
        # check for -command if we didn't find script hooks. if we did read the scripts
        try: 
            if not preValid:
                prehook, preValid = self.config.value(cfgkey+'.hook-client-pre-update-command')
                if preValid:
                    prehook = "#!/bin/bash\n" + prehook
            else:
                f = open(os.path.join(self.HOOK_DIR,prehook))
                prehook = f.read()
                f.close()

            if not postValid:
                posthook, postValid = self.config.value(cfgkey+'.hook-client-post-update-command')
                if postValid:
                    posthook = "#!/bin/bash\n" + posthook
            else:
                f = open(os.path.join(self.HOOK_DIR,posthook))
                posthook = f.read()
                f.close()
        except IOError, e:
            self.log("IOError opening hook file: %s" % e, LOG_ERR)

        if not preValid:
            prehook = ""
        if not postValid:
            posthook = ""

        return (name, files, prehook, posthook)

    def config_get_configs(self, file, host):
        """Return the list of config sources making up config file file on the host host"""
        self.config_cache_configs(host)

        if file in self.host2config[host]:
            config, pre, post = self.host2config[host][file]
            return config
        else:
            return []

    def config_cache_configs(self, host):
        """ Cache all configs for host if host's configs have not already been cached"""
        if host in self.cached_host_configs: # already cached?
            return

        key = host + '.configs'
        for cfgkey in self.config.children(key):
            (name, files, pre, post) = self.config_parse_config_block(cfgkey)
            if not host in self.host2config:
                self.host2config[host] = {}
            self.host2config[host][name] = (files, pre, post) # cache list of file's sources and hooks

        self.cached_host_configs.add(host)

    def config_cache_dirfiles(self, host):
        """ Cache all files in static directories """
        if host in self.cached_host_dirfiles: # already cached?
            return

        # cache files in static directories
        dirout = {'dirs': [], 'files': []}
        for dir in self.host2dir[host]:
            os.path.walk(os.path.join(self.DIR_DIR,dir), self.walk_dir, dirout)
        for file in dirout["files"]:
            if not host in self.host2dirfiles:
                self.host2dirfiles[host] = []
            self.host2dirfiles[host].append(file)
            

    def get_file(self, file, host):
        """ Find file and return a (file, permissions) pair """
        out = ""
        found = False
        perm = None
        for cfg in self.config_get_configs(file, host):
            try:
                filepath = os.path.join(self.CONFIG_DIR,cfg)
                f = open(filepath)
                out += f.read()
                f.close()
                thisperm = stat.S_IMODE(os.stat(filepath).st_mode)
                if perm is None or thisperm < perm:
                    perm = thisperm
                found = True
            except IOError, e:
                self.log("IOError opening file: %s" % e, LOG_ERR)

        # if file not found, check static dirs for it
        if found:
            return (out, perm)
        elif file in self.host2dirfiles[host]:
            try:
                filepath = os.path.join(self.DIR_DIR,file)
                f = open(filepath)
                out += f.read()
                f.close()
                perm = stat.S_IMODE(os.stat(filepath).st_mode)
                return (out, perm)
            except IOError, e:
                self.log("IOError opening file: %s" % e, LOG_ERR)

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
        """ Return the host name for the FQDN host """
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
        """ Determine whether fingerprint is host's fingerprint and return true if so. """
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
            self.log("invalid cert received: %s" % x509.get_subject(), LOG_INFO)
            return False

        if self.config_fingerprint_valid(x509.get_subject().commonName, x509.digest("sha512")):
            return True
        else:
            # unknown host
            self.log("denying connection from a cert that validates but does not exist in the config: %s" % x509.get_subject(), x509.digest("sha512"), LOG_WARNING)
            return False

    def handle_sigusr2(self, signum, frame):
        """ Reload config on SIGUSR2 """
        self.config_reload()

def prepare_server(basedir):
    """ Prepare a ConfigPage object with reasonable defaults and return a (port, Resource, ContextFactory) tuple """
    r = ConfigPage()
    r.BASE_DIR = basedir + os.path.sep
    r.CONFIG_DIR = os.path.join(r.BASE_DIR, "configs") + os.path.sep
    r.DIR_DIR = os.path.join(r.BASE_DIR, "dirs") + os.path.sep
    r.HOOK_DIR = os.path.join(r.BASE_DIR, "hooks") + os.path.sep
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

    signal.signal(signal.SIGUSR2, r.handle_sigusr2)

    return (7080, r, contextFactory)

engine = None

def main():
    if len(sys.argv) > 2:
        print >> sys.stderr, "usage: %s [<base directory>]" % sys.argv[0]
        exit(3)

    if len(sys.argv) == 2:
        basedir = sys.argv[1]
    else:
        basedir = os.path.expanduser("~/.config/syncfgd")

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
