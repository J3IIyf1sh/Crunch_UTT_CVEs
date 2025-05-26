from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from prettytable import PrettyTable
from postgresSQL import Base, Contexte, Client, Equipement, Inventaire, TacheEquipement, CVE, EquipementCVE

# Connexion à la base PostgreSQL
engine = create_engine("postgresql://jellyfish:Jellyfish@localhost/db_cves")
Session = sessionmaker(bind=engine)
session = Session()

# Liste des classes de tables à afficher
tables = [Contexte, Client, Equipement, Inventaire, TacheEquipement, EquipementCVE]

for table_class in tables:
    table_name = table_class.__tablename__
    print(f"\n=== Contenu de la table '{table_name}' ===")

    results = session.query(table_class).all()
    if not results:
        print("Aucune donnée trouvée.")
        continue

    # Construction d'une table avec les colonnes
    columns = [column.name for column in table_class.__table__.columns]
    pretty = PrettyTable()
    pretty.field_names = columns

    for row in results:
        row_data = [getattr(row, col) for col in columns]
        pretty.add_row(row_data)

    print(pretty)

print(f"\n=== Contenu simplifié de la table 'cves' ===")

results = session.query(CVE).all()
if not results:
    print("Aucune donnée trouvée.")
else:
    # Colonnes importantes à afficher
    columns = [
        "id", "cve_id", "base_score", "base_severity",
        "vector_string", "produit", "version_produit", "vendeur"
    ]

    pretty = PrettyTable()
    pretty.field_names = columns + ["description (100c)"]

    for row in results:
        row_data = [getattr(row, col) for col in columns]
        desc = (row.description[:100] + "...") if row.description and len(row.description) > 100 else row.description
        row_data.append(desc)
        pretty.add_row(row_data)

    print(pretty)


session.close()
