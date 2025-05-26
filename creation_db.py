#python postgres sql

from sqlalchemy import create_engine, Column, Integer, String, Float, Text, Date, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class Contexte(Base):
    __tablename__ = 'contextes'

    id = Column(Integer, primary_key=True)
    secteur_activite = Column(String)
    nombre_salaries = Column(Integer)
    nombre_clients = Column(Integer)
    donnees_sensibles = Column(Integer)
    localisation = Column(String)


class Client(Base):
    __tablename__ = 'clients'

    id = Column(Integer, primary_key=True)
    nom_entreprise = Column(String)
    description = Column(Text)
    responsable = Column(String)
    email = Column(String)
    telephone = Column(String)
    risque_total = Column(String)
    contexte_id = Column(Integer, ForeignKey('contextes.id'))


class Equipement(Base):
    __tablename__ = 'equipements'

    id = Column(Integer, primary_key=True)
    marque = Column(String)
    type = Column(String)
    modele = Column(String)
    version = Column(String)
    description = Column(Text)
    firmware = Column(String)


class Inventaire(Base):
    __tablename__ = 'inventaires'

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey('clients.id'))
    equipement_id = Column(Integer, ForeignKey('equipements.id'))
    vlan = Column(Boolean)
    dmz = Column(Boolean)
    expose_internet = Column(Boolean)
    oob = Column(Boolean)
    note_position = Column(Float)


class TacheEquipement(Base):
    __tablename__ = 'taches_equipement'

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey('clients.id'))
    equipement_id = Column(Integer, ForeignKey('equipements.id'))
    description = Column(Text)
    responsable = Column(String)
    lien_planning = Column(String)
    statut = Column(String)  # en_cours, fini, etc.
    date_debut = Column(Date)
    date_fin = Column(Date)


class CVE(Base):
    __tablename__ = 'cves'

    id = Column(Integer, primary_key=True)
    cve_id = Column(String, unique=True)
    description = Column(Text)
    base_score = Column(Float)
    base_severity = Column(String)
    impact_score = Column(Float)
    exploitability_score = Column(Float)
    vector_string = Column(String)
    access_vector = Column(String)
    access_complexity = Column(String)
    authentication = Column(String)
    confidentiality_impact = Column(String)
    integrity_impact = Column(String)
    availability_impact = Column(String)
    weaknesses = Column(Text)  # e.g., "NVD-CWE-Other"
    date_publication = Column(Date)
    date_mise_a_jour = Column(Date)
    cisa_date = Column(Date)
    sources = Column(Text)  # JSON string or concatenated source info
    produit = Column(String)
    version_produit = Column(String)
    vendeur = Column(String)
    cve_change_id = Column(String)


class EquipementCVE(Base):
    __tablename__ = 'equipement_cve'

    equipement_id = Column(Integer, ForeignKey('equipements.id'), primary_key=True)
    cve_id = Column(Integer, ForeignKey('cves.id'), primary_key=True)
    date_detection = Column(Date)
    critique = Column(Boolean)
    impact_description = Column(Text)


# Pour générer la base de données PostgreSQL :
if __name__ == '__main__':
    engine = create_engine("postgresql://jellyfish:Jellyfish@localhost/db_cves")
    Base.metadata.create_all(engine)
    conn = engine.connect()

