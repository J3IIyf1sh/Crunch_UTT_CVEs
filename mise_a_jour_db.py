import requests
import datetime
from datetime import datetime, timedelta
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, text
from postgresSQL import Base, Contexte, Client, Equipement, Inventaire, TacheEquipement, EquipementCVE, CVE
import urllib.parse
import json
import re
import time
from sqlalchemy import insert
from sqlalchemy.dialects.postgresql import insert as pg_insert

API_KEY = "f2e1ddaa-ab13-422d-8a10-1366406cf474"
headers = {"apiKey": API_KEY}

# Connexion à la base
engine = create_engine("postgresql://jellyfish:Jellyfish@localhost/db_cves")
Session = sessionmaker(bind=engine)
session = Session()
# Définir une période de 24h
end_time = datetime.utcnow()
start_time = end_time - timedelta(days=3)
# Format ISO-8601 avec timezone explicite
tz = "+01:00"  # PAS encodé ici
start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%S.000") + tz
end_iso = end_time.strftime("%Y-%m-%dT%H:%M:%S.000") + tz

# Requête à l'API CVE History
url = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0/"
params = {
    "changeStartDate": start_iso,
    "changeEndDate": end_iso
}
response = requests.get(url,headers=headers,params=params)
print(f"Request URL: {response.url}")  # pour debug

if response.status_code == 200:
    data = response.json()
    print(data)
else:
    print(f"Erreur {response.status_code}")





def extract_vector(metrics):
    version_keys = [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0")
    ]
    for key, _ in version_keys:
        if key in metrics:
            for entry in metrics[key]:
                data = entry.get("cvssData")
                if data and "vectorString" in data:
                    return data["vectorString"]
    return None

def extract_cvss_metrics(metrics):
    result = {
        "base_score": None,
        "base_severity": None,
        "impact_score": None,
        "exploitability_score": None,
        "access_vector": None,
        "access_complexity": None,
        "authentication": None,
        "confidentiality_impact": None,
        "integrity_impact": None,
        "availability_impact": None
    }

    version_keys = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ]

    for key in version_keys:
        if key in metrics:
            for entry in metrics[key]:
                data = entry.get("cvssData")
                if data:
                    result["base_score"] = data.get("baseScore")
                    result["base_severity"] = data.get("baseSeverity")
                    result["access_vector"] = data.get("attackVector")
                    result["access_complexity"] = data.get("attackComplexity")
                    result["authentication"] = data.get("authentication", None)
                    result["confidentiality_impact"] = data.get("confidentialityImpact")
                    result["integrity_impact"] = data.get("integrityImpact")
                    result["availability_impact"] = data.get("availabilityImpact")
                result["impact_score"] = entry.get("impactScore")
                result["exploitability_score"] = entry.get("exploitabilityScore")
                return result
    return result

def extract_cpe_components(cpe_string):
    parts = cpe_string.split(":")
    return {
        "vendeur": parts[3] if len(parts) > 3 else None,
        "produit": parts[4] if len(parts) > 4 else None,
        "version": parts[5] if len(parts) > 5 else None
    }

def extract_description(descriptions):
    for d in descriptions:
        if d.get("lang", "").lower() == "en":
            return d.get("value")
    return None

def extract_cisa_date(change):
    # Pareil, selon les données, par ex. dans les sources ou un champ dédié
    # Si l’API fournit pas directement, tu peux laisser None
    return None

with engine.begin() as conn:
    for item in data.get("cveChanges", []):
        change = item.get("change", {})
        cve_id = change.get("cveId")
        if not cve_id:
            continue
        cve_change_id = change.get("cveChangeId") or cve_id
        print(f"cve_change_id: {cve_change_id}")
        # Vérifier la date de dernière mise à jour dans la base
        db_result = conn.execute(text("""
            SELECT date_mise_a_jour FROM cves WHERE cve_change_id = :cve_change_id
        """), {"cve_change_id": cve_change_id}).fetchone()
        
        
        # Si présente et date identique => ne rien faire
        if db_result:
            print(f"{cve_id} déjà traité via ce cveChangeId ({cve_change_id}), on passe.")
            continue

        # Faire la requête complète pour cette CVE
        cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        print(f"Requête vers : {cve_url}")

        try:
            cve_response = requests.get(cve_url, headers=headers, timeout=10)
            cve_response.raise_for_status()
            cve_data = cve_response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la requête pour {cve_id} : {e}")
            time.sleep(5)
            continue
        except ValueError:
            print(f"Réponse JSON invalide pour {cve_id}")
            continue

        if "vulnerabilities" not in cve_data or not cve_data["vulnerabilities"]:
            print(f"Aucune donnée détaillée pour {cve_id}")
            continue

        vuln = cve_data["vulnerabilities"][0]
        cve_info = vuln["cve"]

        # Extraction des données
        description = extract_description(cve_info.get("descriptions", []))
        vector_string = extract_vector(cve_info.get("metrics", []))
        cvss_metrics = extract_cvss_metrics(cve_info.get("metrics", []))
        weaknesses = [d.get("value") for w in cve_info.get("weaknesses", []) for d in w.get("description", []) if d.get("value")]
        sources = [s.get("url") for s in cve_info.get("references", []) if s.get("url")]

        configurations = cve_info.get("configurations", [])
        vendeur = produit = version_produit = None
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if "criteria" in cpe_match:
                        cpe_data = extract_cpe_components(cpe_match["criteria"])
                        vendeur = cpe_data.get("vendeur")
                        produit = cpe_data.get("produit")
                        version_produit = cpe_data.get("version")
                        break
                if vendeur: break
            if vendeur: break

        date_publication = cve_info.get("published")
        date_mise_a_jour = cve_info.get("lastModified")
        
        sql_params = {
            "cve_id": cve_id,
            "description": description,
            "base_score": cvss_metrics["base_score"],
            "base_severity": cvss_metrics["base_severity"],
            "impact_score": cvss_metrics["impact_score"],
            "exploitability_score": cvss_metrics["exploitability_score"],
            "vector_string": vector_string,
            "access_vector": cvss_metrics["access_vector"],
            "access_complexity": cvss_metrics["access_complexity"],
            "authentication": cvss_metrics["authentication"],
            "confidentiality_impact": cvss_metrics["confidentiality_impact"],
            "integrity_impact": cvss_metrics["integrity_impact"],
            "availability_impact": cvss_metrics["availability_impact"],
            "weaknesses": ", ".join(weaknesses),
            "date_publication": date_publication,
            "date_mise_a_jour": date_mise_a_jour,
            "sources": ", ".join(sources),
            "cisa_date": None,
            "produit": produit,
            "version_produit": version_produit,
            "vendeur": vendeur,
            "cve_change_id": cve_change_id
        }

        stmt = pg_insert(CVE.__table__).values(**sql_params)
        # Sur conflit de cve_id, mettre à jour tous les champs
        update_dict = {col: stmt.excluded[col] for col in sql_params.keys() if col != 'cve_id'}
        stmt = stmt.on_conflict_do_update(
            index_elements=['cve_id'],
            set_=update_dict
        )

        # Exécution de l'UPSERT
        result = conn.execute(stmt)
        if result.rowcount == 1:
            print(f"{cve_id} inséré ou mis à jour en base.")

    conn.commit()
