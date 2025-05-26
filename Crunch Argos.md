
## Installation de la base de données sous Linux 
### Installer PostgreSQL

```bash 
sudo apt update 
sudo apt install postgresql postgresql-contrib 
sudo service postgresql start
sudo service enable postgresql
```
### Se connecter à PostgreSQL
```bash
sudo -u postgres psql
```
### Créer un utilisateur et une base de données
Dans l'interface `psql` :
```postgresql
CREATE USER jellyfish WITH SUPERUSER CREATEDB CREATEROLE LOGIN PASSWORD 'Jellyfish'; CREATE DATABASE db_cves OWNER jellyfish; \q
```
adapter `jellyfish` et `db_cves` en fonction des besoins.
### Installer SQLAlchemy et psycopg2 pour Python
```
pip3 install sqlalchemy psycopg2
```
### Vérification de la connexion avec SQLAlchemy
Exemple de chaîne de connexion Python :
```python
from sqlalchemy import create_engine
engine = create_engine("postgresql://jellyfish:Jellyfish@localhost/db_cves")
conn = engine.connect()
print("Connexion réussie à PostgreSQL !")
```
### Schéma de la base de données
_visualisation à https://dbdiagram.io/d_
![[Capture d’écran 2025-05-23 à 10.47.21.png]]
``` mysql

Table clients {
id serial [pk]
nom_entreprise varchar
description text
responsable varchar
email varchar
telephone varchar
risque varchar
contexte_id int [ref: > contextes.id]
}
Table contextes {
id serial [pk]
secteur_activite varchar
nombre_salaries int
nombre_clients int
donnees_sensibles int
localisation varchar
}
Table inventaires {
id serial [pk]
client_id int [ref: > clients.id]
equipement_id int [ref: > equipements.id]
vlan boolean
dmz boolean
expose_internet boolean
oob boolean
position_reseau varchar
note_position float
}
Table equipements {
id serial [pk]
marque varchar
type varchar
modele varchar
version varchar
description text
firmware varchar
}
Table taches_equipement {
id serial [pk]
client_id int [ref: > clients.id]
equipement_id int [ref: > equipements.id]
description text
responsable varchar
lien_planning varchar
statut varchar // en_cours, fini, etc.
date_debut date
date_fin date
}
Table cves {
id serial [pk]
cve_id varchar [unique]
score_cve float
resume text
score_cvss float
vecteur_cvss varchar
date_publication date
date_mise_a_jour date
sources text
cisa_date date
produit varchar
version_produit varchar
vendeur varchar
}
Table equipement_cve {
equipement_id int [ref: > equipements.id]
cve_id int [ref: > cves.id]
date_detection date
critique boolean
impact_description text
primary key (equipement_id, cve_id)
}
```
--> on peut faire un script python pour créer cette base de données. 
--> on peut faire un scrip python pour remplir cette base aléatoirement pour faire un test de fonctionnement lorsqu'il n'existe pas de vraies valeurs. 
### Connexion à la base de données avec notre utilisateur 
```bash
psql -h localhost -U jellyfish -d db_cves
```
#### Voir les tables de la base de données
```postgres
db_cves=# \dt

               List of relations

 Schema |       Name        | Type  |   Owner   

--------+-------------------+-------+-----------

 public | clients           | table | jellyfish

 public | contextes         | table | jellyfish

 public | cves              | table | jellyfish

 public | equipement_cve    | table | jellyfish

 public | equipements       | table | jellyfish

 public | inventaires       | table | jellyfish

 public | taches_equipement | table | jellyfish

(7 rows)
```
### Les sauvegarder dans un fichier en dehors de psql
```postgres
\o resultats.txt
SELECT * FROM clients;
\o
```

### Voir les champs d'une table 
```
\d ma_table
```
### Voir certains champs de la table en particulier 
```postgres
SELECT cve_id, base_score, date_publication, vendeur
FROM public.cves
ORDER BY date_publication DESC;
```
### Supprimer une table 
```postgres
DELETE FROM cves;
```

# Fonctionnement
### Partie rapport 
#### Synchronisation des vulnérabilités : une collecte automatisée et intelligente via l’API NVD

Un des éléments clés du projet ARGOS repose sur la capacité à **alimenter automatiquement et de manière fiable** notre base de données interne avec les dernières vulnérabilités référencées à l’échelle mondiale. Pour cela, nous avons fait le choix de nous appuyer sur la **base NVD (National Vulnerability Database)**, maintenue par le gouvernement américain. C’est une référence incontournable dans le monde de la cybersécurité, qui fournit des informations détaillées, vérifiées et enrichies pour chaque CVE publiée.

##### Pourquoi utiliser une API et pourquoi celle de la NVD ?

Le choix de passer par une API s’est imposé naturellement. Une API (Application Programming Interface) permet d’accéder à des données de manière automatisée, structurée et standardisée, sans avoir à scraper manuellement du contenu web ou dépendre de formats instables. Elle offre une garantie de pérennité et une flexibilité dans les filtres utilisés (dates, scores, produits, etc.).

Parmi toutes les sources potentielles de CVE, nous avons comparé plusieurs options. La NVD s’est distinguée par :

- La **qualité des données** (détail technique, scores CVSS, liens vers les correctifs, description des impacts, etc.)
    
- La **disponibilité d’une API REST stable**, bien documentée, et supportée par une institution fiable
    
- La **structure claire des données**, avec des identifiants normalisés (CVE ID, CPE, CWE) compatibles avec nos modèles relationnels
    

Nous avons ainsi retenu l’API officielle de la NVD, disponible à l’adresse :

ruby

CopierModifier

`https://services.nvd.nist.gov/rest/json/cves/2.0/`

Cette API nous permet de **filtrer les vulnérabilités par date**, ce qui est essentiel pour la mise à jour incrémentale, mais aussi d'accéder à des métadonnées essentielles comme :

- Le score CVSS (v2 et v3)
    
- La sévérité (low, medium, high, critical)
    
- Les produits concernés (via CPE)
    
- Les faiblesses exploitées (via CWE)
    
- Les descriptions détaillées
    
- Les dates de publication et de mise à jour
    

---

####  Un fonctionnement en deux étapes : d’abord l’historique, puis la mise à jour quotidienne

##### 1. Récupération initiale de l’historique

Lorsque la plateforme ARGOS est lancée pour la première fois, notre base de données est encore vide. Il est donc nécessaire de **remonter dans le temps** pour collecter l’ensemble des vulnérabilités existantes jusqu’à aujourd’hui. Cette étape initiale s’appuie sur un script de récupération en boucle, qui télécharge les CVE par tranches de dates successives, jusqu’à constituer un historique complet dans la base PostgreSQL.

Cette phase unique, longue mais indispensable, permet de poser les fondations pour toutes les analyses futures, notamment les corrélations entre produits clients et CVE.

##### 2. Mise à jour quotidienne via la synchronisation

Une fois cet historique installé, notre système entre en **mode de surveillance continue**. Chaque jour, un script est exécuté automatiquement (via un cron job ou un scheduler) pour interroger l’API de la NVD sur les **24 dernières heures**.

L’intérêt de cette synchronisation régulière est triple :

- **Ne récupérer que l’essentiel**, en limitant le volume de données à analyser
    
- **Détecter les nouvelles CVE dès leur publication**, et ainsi prévenir rapidement les clients concernés
    
- **Identifier les CVE déjà connues mais modifiées**, car la NVD met parfois à jour des descriptions, scores ou impacts
    

---

#### Détails techniques de l’algorithme de collecte

Le script est écrit en Python, avec SQLAlchemy comme ORM pour interagir avec la base PostgreSQL. Cette approche permet une gestion propre et maintenable des objets base de données, tout en évitant les erreurs liées au SQL brut.

Voici les principales étapes du processus :

1. **Connexion à la base PostgreSQL** :  
    Le script établit une connexion via SQLAlchemy, en important les modèles de table (notamment `CVE`) depuis un fichier centralisé.
    
2. **Définition de la plage temporelle** :  
    La fenêtre analysée est fixée à 24 heures (du jour précédent à maintenant), au format ISO-8601 pour compatibilité avec l’API.
    
3. **Appel à l’API** :  
    Une requête GET est envoyée à l’URL de l’API NVD avec les paramètres de dates. En cas de réponse valide (code HTTP 200), les données sont converties en JSON.
    
4. **Analyse des CVE une par une** :  
    Chaque élément du tableau `vulnerabilities` est traité individuellement. Pour chaque CVE :
    
    - Le script **vérifie si elle est déjà présente en base** (via son `cve_id`)
        
    - Si elle est absente ou modifiée, il **extrait les champs clés** : description, score, criticité, CPE, CWE, etc.
        
    - Il utilise des méthodes robustes `.get()` avec valeurs par défaut pour éviter les erreurs sur des champs manquants
        
5. **Mise en base** :  
    Les objets CVE sont construits comme des instances Python et ajoutés à la session SQLAlchemy. Une fois le traitement terminé, `session.commit()` permet d’insérer ou de mettre à jour en base.
    

---

#### Pourquoi cette architecture est adaptée à un contexte RSE

Enfin, cette stratégie de collecte, bien que technique, s’inscrit dans une **logique de sobriété numérique et de responsabilité** :

- Elle évite de surcharger inutilement l’API ou notre base de données
    
- Elle permet d’**économiser de la bande passante** et du temps processeur
    
- Elle garantit que seules les données pertinentes sont traitées, évitant le gaspillage de ressources
    

C’est un exemple concret d’une **cybersécurité éthique**, qui cherche à concilier **efficacité, pertinence, transparence et durabilité**.

## NVD API Key Activated

Thank you for confirming your request for an NVD API key. Please securely save this key. 

```python
f2e1ddaa-ab13-422d-8a10-1366406cf474  
```

# Utilisation
### Recherches des vulnérabilités

```python
python3 double_requests.py
```
### Visualisation des tables
```python
python3 affichage.py
```

![[Capture d’écran 2025-05-23 à 11.13.27.png]]![[Capture d’écran 2025-05-23 à 11.14.22.png]]
