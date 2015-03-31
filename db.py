from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class DomainInfo(Base):
	__tablename__ = 'domain_info'
	id = Column(Integer, primary_key=True)
	domain = Column(String(250), nullable=False)
	ip = Column(String(250))
	whois = Column(String(25000))
	loc = Column(String(5000))
	fp = Column(String(5000))
	
