syncfg
======
syncfg is a system for synchronizing config files and supporting directories.

Config files are comprised of config "sources" (or "parts") that are appended in order to create the final config file. The list of config sources comprising each config file can be different for each host.

syncfg provides two advantages over traditional configuration management:

- configs are only edited once and in one place (the syncfgd server), and may easily be managed with git there
- changes to a config are propagated to all clients with no manual intervention, even if the final config differs between clients

As you may imagine, this requires that one chooses logical config parts. Static directories exist to help keep scripts and libraries in sync, such as the elisp in .emacs.d/lisp/. Directories are not host-specific and are not made up of multiple parts as configs are.

Example
=======
hostA's .emacs might be made of the sources "emacs/common", "emacs/python", and "emacs/haskell". On hostB, which does not have a Haskell development environment but does have a Java dev environment, "emacs/haskell" is replaced with "emacs/java". Making a change to "emacs/python" would update the .emacs file on both hostA and hostB.

Supporting elisp can be pushed to both hostA and hostB by configuring a ".emacs.d/lisp" static directory.

Requirements
============
- libconfig (on Ubuntu systems install the libconfig++8-dev package)
- Python
- python-libconfig (currently at http://github.com/azeey/python-libconfig)
- Twisted (python-twisted-core and python-twisted-web on Ubuntu)

Setup
=====
Server
------
- Create a CA, create a server cert signed with it, create client certs signed with it, and distribute the client certs to your clients
  The easy-rsa scripts from OpenVPN are the easiest way to do this. See /usr/share/doc/openvpn/examples/easy-rsa/2.0
- On the server, the following certs should be present in the base directory (~/.config/syncfgd/):
  keys/ca.crt
  keys/server.crt
  keys/server.key
  If you want to store the SSL certs in an alternate location, edit service.tac.
- Rename config.sample to config, copy to your base directory (~/.config/syncfgd/), and edit it
- Create your config file parts in the configs directory in your base directory (~/.config/syncfgd/configs)

  By convention config parts are placed in a directory named after the config file they are used to generate.
  For example, the config parts used to generate .zshrc might be stored in "~/.config/syncfgd/configs/zshrc/common" and "~/.config/syncfgd/configs/zshrc/emacsclient"
- Populate the dirs directory with any required static files (~/.config/syncfgd/dirs)
- Launch the daemon with twistd -ny service.tac or use the start-server.sh and stop-server.sh scripts
- To reload the config file, send SIGUSR2 to the daemon's process

Client
------
- Place the CA's public cert (ca.crt), and the client's public and private certs on the client
- Copy client-config.sample to ~/.config/syncfg/config and edit
- To update all configs and directories, run: ./syncfg -u
- To update specific resources on a client, run: ./syncfg -f ~/.a_file_to_update -f ~/file2 -d ~/dir1 -d ~/dir2
- To view all managed configs and dirs for a host, run: ./syncfg -l
- Use --verbose or the -v flag to see information on each file and directory that is processed

License
=======
syncfg is available under the GNU General Public License v2, or (at your option) any later version.
