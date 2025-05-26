from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from faker import Faker
import random
from datetime import date, timedelta

from postgresSQL import Base, Contexte, Client, Equipement, Inventaire, TacheEquipement, EquipementCVE

# Connexion
DATABASE_URL = "postgresql://jellyfish:Jellyfish@localhost/db_cves"
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Générateur aléatoire
faker = Faker()

# --- Création de données cohérentes ---

def create_contextes(n=5):
    contextes = []
    for _ in range(n):
        contexte = Contexte(
            secteur_activite=random.choice(["Finance", "Santé", "Éducation", "Technologie", "Transport"]),
            nombre_salaries=random.randint(10, 500),
            nombre_clients=random.randint(5, 1000),
            donnees_sensibles=random.randint(0, 10),
            localisation=random.choice(["Paris", "Lyon", "Toulouse", "Marseille", "Nantes"])
        )
        session.add(contexte)
        contextes.append(contexte)
    session.commit()
    return contextes

def create_clients(contextes, n=10):
    clients = []
    for _ in range(n):
        contexte = random.choice(contextes)
        client = Client(
            nom_entreprise=faker.company(),
            description=faker.text(),
            responsable=faker.name(),
            email=faker.company_email(),
            telephone=faker.phone_number(),
            risque_total=random.choice(["faible", "moyen", "élevé"]),
            contexte_id=contexte.id
        )
        session.add(client)
        clients.append(client)
    session.commit()
    return clients

def create_equipements(n=10):
    equipements = []
    marques = ["Cisco", "Juniper", "Fortinet", "Palo Alto", "HP"]
    types = ["Routeur", "Switch", "Firewall", "Serveur"]
    for _ in range(n):
        equipement = Equipement(
            marque=random.choice(marques),
            type=random.choice(types),
            modele=faker.bothify(text="Model-###"),
            version=f"{random.randint(1, 5)}.{random.randint(0, 9)}",
            description=faker.text(),
            firmware=faker.bothify(text="FW-??-##")
        )
        session.add(equipement)
        equipements.append(equipement)
    session.commit()
    return equipements

def create_inventaire(clients, equipements, n=20):
    for _ in range(n):
        inventaire = Inventaire(
            client_id=random.choice(clients).id,
            equipement_id=random.choice(equipements).id,
            vlan=random.choice([True, False]),
            dmz=random.choice([True, False]),
            expose_internet=random.choice([True, False]),
            oob=random.choice([True, False]),
            note_position=round(random.uniform(1.0, 5.0), 2)
        )
        session.add(inventaire)
    session.commit()

def create_taches(clients, equipements, n=15):
    for _ in range(n):
        date_debut = faker.date_between(start_date="-30d", end_date="today")
        date_fin = date_debut + timedelta(days=random.randint(1, 10))
        tache = TacheEquipement(
            client_id=random.choice(clients).id,
            equipement_id=random.choice(equipements).id,
            description=faker.text(),
            responsable=faker.name(),
            lien_planning=faker.url(),
            statut=random.choice(["en_cours", "fini", "à_planifier"]),
            date_debut=date_debut,
            date_fin=date_fin
        )
        session.add(tache)
    session.commit()

def create_equipement_cve_fake_links(equipements, n=10):
    """Simule des lignes EquipementCVE sans lier à des vraies CVEs (juste pour tester l'intégration)"""
    for _ in range(n):
        equipement = random.choice(equipements)
        equip_cve = EquipementCVE(
            equipement_id=equipement.id,
            cve_id=1,  # FAUX ID ! À remplacer après import des CVEs
            date_detection=faker.date_between(start_date="-100d", end_date="today"),
            critique=random.choice([True, False]),
            impact_description=faker.text()
        )
        session.add(equip_cve)
    session.commit()

# --- Exécution ---

if __name__ == "__main__":
    print("Création de données factices...")

    contextes = create_contextes()
    clients = create_clients(contextes)
    equipements = create_equipements()
    create_inventaire(clients, equipements)
    create_taches(clients, equipements)
    # Pas de CVE réelle : on évite create_equipement_cve_fake_links

    print("Remplissage terminé avec succès ✅")
