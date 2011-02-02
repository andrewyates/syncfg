from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation, sessionmaker
 
Base = declarative_base()
 
class Config(Base):
    __tablename__ = 'configs'
 
    id = Column(Integer, primary_key=True)
    file = Column(String(255), nullable=False)
    host_id = Column(Integer, ForeignKey('hosts.id'))
	
    def __init__(self, file=None, host=None):
        self.file = file
        self.host = host
    def __repr__(self):
        return "Config(%r, %r, %r)" % (self.id, self.file, self.host_id)
 
class ConfigPart(Base):
    __tablename__ = 'config_parts'
 
    id = Column(Integer, primary_key=True)
    config_id = Column(Integer, ForeignKey('configs.id'))
    rank = Column(Integer, nullable=False)
    file = Column(String(255), nullable=False)
 
    def __init__(self, config_id=None, rank=None, file=None):
        self.config_id = config_id
        self.rank = rank
        self.file = file
 
    def __repr__(self):
        return ("ConfigPart(%r, %r, %r, %r)" % 
                (self.id, self.config_id, self.rank, self.file))

class Host(Base):
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    hostname = Column(String(255), nullable=False)
    fingerprint = Column(String(255), nullable=False)

    def __init__(self, hostname=None, fingerprint=None):
        self.hostname = hostname
        self.fingerprint = fingerprint

    def __repr__(self):
        return ("Host(%r, %r, %r)" %
                (self.id, self.hostname, self.fingerprint))

class Dir(Base):
    __tablename__ = 'dirs'
    
    id = Column(Integer, primary_key=True)
    dir = Column(String(255), nullable=False)
    
    def __init__(self, dir=None):
        self.dir = dir

    def __repr__(self):
        return ("Dir(%r, %r)" %
                (self.id, self.dir))
    
class DirHost(Base):
    __tablename__ = 'dir_hosts'

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    dir_id = Column(Integer, ForeignKey('dirs.id'))

    def __init__(self, host_id=None, dir_id=None):
        self.host_id = host_id
        self.dir_id = dir_id

    def __repr__(self):
        return ("DirHost(%r, %r, %r)" %
                (self.id, self.host_id, self.dir_id))

def init_engine(url):
    engine =  create_engine(url)
    Base.metadata.create_all(engine)
    return engine
