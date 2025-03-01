import os
import certstream
import subprocess
import json
import time
import dns.resolver
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from ipwhois import IPWhois
import threading

# CONFIGURATION / Change ME

BRAND_DOMAINS = [
    "microsoft.com", "windows.com", "office.com", "outlook.com", "live.com", "hotmail.com", "azure.com",
    "google.com", "gmail.com", "youtube.com", "android.com",
    "apple.com", "icloud.com", "appleid.apple.com",
    "amazon.com", "aws.amazon.com", "s3.amazonaws.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "linkedin.com", "snapchat.com",
    "paloaltonetworks.com", "fortinet.com", "checkpoint.com", "sophos.com", "crowdstrike.com",
    "sentinelone.com", "trendmicro.com", "mcafee.com", "symantec.com", "kaspersky.com",
    "ubuntu.com", "debian.org", "redhat.com", "fedora.org", "centos.org", "suse.com", "archlinux.org",
    "cisco.com", "juniper.net", "netgear.com", "tp-link.com", "watchguard.com", "zyxel.com", "avaya.com",
    "cloudflare.com", "digitalocean.com", "heroku.com", "kubernetes.io", "docker.com", "github.com",
    "gitlab.com", "bitbucket.org",
    "zoom.us", "slack.com", "teams.microsoft.com", "webex.com",
    "paypal.com", "stripe.com",
    "ameli.fr", "impots.gouv.fr",
    "oracle.com", "ibm.com", "adobe.com"
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT", "NS"]

ES_URL = "http://localhost:9200"
ES_PASSWORD = os.getenv("ES_PASSWORD", "GZEL=CHANGE_ME")
ES_INDEX = "passivedns"

# Connexion Elasticsearch
es = Elasticsearch(
    ES_URL,
    basic_auth=("elastic", ES_PASSWORD),
)

# Vérification connexion ES
try:
    if not es.ping():
        raise Exception("Elasticsearch connection failed. Check credentials or Elasticsearch status.")
    print("[+] Successfully connected to Elasticsearch.")
except Exception as e:
    print(f"[!] Elasticsearch connection error: {e}")
    exit(1)

# Vérification/création de l'index
if not es.indices.exists(index=ES_INDEX):
    mapping = {
        "mappings": {
            "properties": {
                "domain":       {"type": "keyword"},
                "timestamp":    {"type": "date"},
                "record_type":  {"type": "keyword"},
                "record_value": {"type": "keyword"},
                "source":       {"type": "keyword"},
                "certificate":  {"type": "object"},
                "hosting":      {"type": "object"},
                # Champs pour la logique de retry
                "no_dns_records":  {"type": "boolean"},
                "retry_count":     {"type": "integer"},
                "next_retry":      {"type": "date"}
            }
        }
    }
    es.indices.create(index=ES_INDEX, body=mapping)
    print(f"[+] Index '{ES_INDEX}' created in Elasticsearch.")


# FONCTIONS


def resolve_dns(domain: str):
    # recup DNS record (A, AAAA, etc.) pour un domaine, si existante +     Retourne une liste de tuples (rtype, rvalue).

    
    results = []
    # Retire tout trailing dot éventuel
    domain = domain.rstrip('.')

    for rtype in DNS_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            for rdata in answers:
                results.append((rtype, str(rdata)))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass
        except Exception as e:
            print(f"[!] Unexpected DNS error for {domain} ({rtype}): {e}")
    return results

def get_hosting_info(dns_records):
    
    # Utilise ipwhois pour récupérer des infos sur l'hébergeur (RDAP).
    
    hosting_info = []
    for rtype, rvalue in dns_records:
        if rtype == "A":
            ip = rvalue
            try:
                obj = IPWhois(ip)
                results = obj.lookup_rdap(depth=1)
                hosting_info.append(results)
            except Exception as e:
                hosting_info.append({"ip": ip, "error": str(e)})
    return hosting_info

def store_dns_records(domain: str, dns_records, source="unknown",
                      certificate=None, hosting=None, retry_count=0):
    """
    Stocke dans ES :
      - Soit des docs pour chaque record_type si on en a trouvé
      - Soit un doc 'no_dns_records' si la liste est vide
    """

    timestamp = datetime.utcnow().isoformat()
    domain = domain.rstrip('.')  # retire trailing dot

    if dns_records:
        # on a trouvé des DNS => on crée un doc par enregistrement
        for (rtype, rvalue) in dns_records:
            doc = {
                "domain": domain,
                "timestamp": timestamp,
                "record_type": rtype,
                "record_value": rvalue,
                "source": source,
                "no_dns_records": False,   # on a trouvé
                "retry_count": retry_count
            }
            if certificate:
                doc["certificate"] = certificate
            if hosting:
                doc["hosting"] = hosting
            es.index(index=ES_INDEX, body=doc)

        print(f"[+] Stored {len(dns_records)} DNS records for '{domain}' (source={source}).")

    else:
        # aucun enregistrement DNS => on crée un doc "no_dns_records"
        doc = {
            "domain": domain,
            "timestamp": timestamp,
            "record_type": None,
            "record_value": None,
            "source": source,
            "no_dns_records": True,
            "retry_count": retry_count
        }
        if certificate:
            doc["certificate"] = certificate

        # Calcul du prochain retry en fonction de retry_count
        if retry_count == 0:
            delta = timedelta(hours=10)    # 10h
        elif retry_count == 1:
            delta = timedelta(days=10)     # 10j
        elif retry_count == 2:
            delta = timedelta(days=30)     # 30j
        else:
            delta = timedelta(days=180)    # 6 mois

        next_retry = datetime.utcnow() + delta
        doc["next_retry"] = next_retry.isoformat()

        es.index(index=ES_INDEX, body=doc)
        print(f"[!] No DNS for '{domain}' => next retry at {next_retry}")

def run_dnstwist(domain: str):
# lance DNS twist pour trouver des domaines de phishing
    command = ["dnstwist", "--registered", "--format", "json", domain]
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=60)
        data = json.loads(output)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError):
        return []
    permutations = [entry["domain"] for entry in data if entry.get("dns_a")]
    return permutations

def process_brand_domains():
# fonction pour set up les permutation pour trouver des domaines de typosquatting
    for domain in BRAND_DOMAINS:
        print(f"[*] Checking dnstwist for sensitive domain: {domain}")
        permutations = run_dnstwist(domain)
        print(f"[+] Found {len(permutations)} active permutations for {domain}.")
        for perm_domain in permutations:
            dns_records = resolve_dns(perm_domain)
            hosting_info = get_hosting_info(dns_records)
            store_dns_records(perm_domain, dns_records, source="dnstwist", hosting=hosting_info)

def process_certstream_message(message, context):

# process domaines provided par Certstream
  
    data = message.get("data", {})
    leaf_cert = data.get("leaf_cert", {})
    all_domains = leaf_cert.get("all_domains", [])

    certificate_info = {
        "subject": leaf_cert.get("subject"),
        "issuer": leaf_cert.get("issuer"),
        "fingerprint": leaf_cert.get("fingerprint"),
        "not_before": leaf_cert.get("not_before"),
        "not_after": leaf_cert.get("not_after")
    }

    for domain in all_domains:
        # on retire le *. et un trailing dot éventuel
        domain = domain.lower().lstrip("*.").rstrip(".")
        if "." not in domain or len(domain) < 4:
            continue

        dns_records = resolve_dns(domain)
        hosting_info = get_hosting_info(dns_records)
        store_dns_records(domain, dns_records,
                          source="certstream",
                          certificate=certificate_info,
                          hosting=hosting_info)

def start_certstream_listener():
    print("[*] Connecting to CertStream...")
    certstream.listen_for_events(process_certstream_message, url='wss://certstream.calidog.io/')


# FONCTION DE RETRY (si le certif n'est pas encore associé à un domaine)

def retry_dns_records():
    """
    Recherche les documents no_dns_records = True
    dont next_retry <= now, supprime l'ancien doc
    puis retente la résolution DNS avec retry_count + 1
    """
    now_str = datetime.utcnow().isoformat()
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"no_dns_records": True}},
                    {"range": {"next_retry": {"lte": now_str}}}
                ]
            }
        }
    }
    resp = es.search(index=ES_INDEX, body=query, size=1000)
    hits = resp["hits"]["hits"]
    print(f"[Retry] Found {len(hits)} documents needing retry.")

    for hit in hits:
        doc = hit["_source"]
        doc_id = hit["_id"]
        domain = doc["domain"]
        old_retry_count = doc.get("retry_count", 0)

        # on supprime l'ancien doc "no_dns_records"
        es.delete(index=ES_INDEX, id=doc_id)

        # retente
        dns_records = resolve_dns(domain)
        hosting_info = get_hosting_info(dns_records)
        store_dns_records(
            domain,
            dns_records,
            source="retry",
            hosting=hosting_info,
            retry_count=old_retry_count + 1
        )


# MAIN

def main():
    print("[*] Initial scan of sensitive domains via dnstwist (comment/uncomment si voulu).")
    # process_brand_domains()  

    # Lancement du listener CertStream dans un thread
    certstream_thread = threading.Thread(target=start_certstream_listener, daemon=True)
    certstream_thread.start()

    print("[*] CertStream listener started (thread). Press Ctrl+C to exit.")

    try:
        while True:
            # On check les retries toutes les 5 minutes / ==> to-do vérifier si trop de charge
            retry_dns_records()
            time.sleep(300)
    except KeyboardInterrupt:
        print("[!] User interruption. Exiting.")

if __name__ == "__main__":
    main()
