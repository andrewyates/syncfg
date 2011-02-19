"""
This is a .tac file for launching the syncfgd service in daemon.py
Change the configuration options in the CONFIG section below and run with: twisted -ny service.tac
The daemon may also be started by running daemon.py directly with BASE_DIR as an argument
"""

import os

from twisted.application import service, internet
from twisted.web import static, server

import daemon

#################################### CONFIG ####################################
# create a configPage with BASE_DIR set to "/home/andrew/tmp/syncfg"
basedir = "~/.config/syncfgd"
port, configPage, contextFactory = daemon.prepare_server(os.path.expanduser(basedir))

# with these defaults:
#configPage.PRIVKEY = os.path.join(configPage.BASE_DIR,'keys/server.key')
#configPage.PUBKEY = os.path.join(configPage.BASE_DIR, 'keys/server.crt')
#configPage.CA_PUBKEY = os.path.join(configPage.BASE_DIR,"keys/ca.crt")
#configPage.CONFIG_FILE = os.path.join(configPage.BASE_DIR, "config")

################################################################################

configPage.config_load()

application = service.Application("syncfgd")
site = server.Site(configPage)
service = internet.SSLServer(port, site, contextFactory)
service.setServiceParent(application)
