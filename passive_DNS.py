import certstream
import subprocess
import json
import time
import dns.resolver
from datetime import datetime
from elasticsearch import Elasticsearch


# domains likely to be typosquatted by attacker
BRAND_DOMAINS = [
    # -- Editeurs et services Microsoft --
    "microsoft.com",
    "windows.com",
    "office.com",
    "outlook.com",
    "live.com",
    "hotmail.com",
    "azure.com",

    # -- Google / Alphabet --
    "google.com",
    "gmail.com",
    "youtube.com",
    "android.com",

    # -- Apple --
    "apple.com",
    "icloud.com",
    "appleid.apple.com",

    # -- Amazon --
    "amazon.com",
    "aws.amazon.com",
    "s3.amazonaws.com",

    # -- Facebook / Meta --
    "facebook.com",
    "instagram.com",
    "whatsapp.com",

    # -- Autres GAFAM / réseaux sociaux --
    "twitter.com",  # ou x.com
    "linkedin.com",
    "snapchat.com",

    # -- Cybersecurity Vendors --
    "paloaltonetworks.com",
    "fortinet.com",
    "checkpoint.com",
    "sophos.com",
    "crowdstrike.com",
    "sentinelone.com",
    "trendmicro.com",
    "mcafee.com",
    "symantec.com",  # maintenant Broadcom
    "kaspersky.com",

    # -- Distributions Linux --
    "ubuntu.com",
    "debian.org",
    "redhat.com",
    "fedora.org",
    "centos.org",
    "suse.com",
    "archlinux.org",

    # -- Appliances / Réseau --
    "cisco.com",
    "juniper.net",
    "netgear.com",
    "tp-link.com",
    "watchguard.com",
    "zyxel.com",
    "avaya.com",

    # -- Cloud & DevOps --
    "cloudflare.com",
    "digitalocean.com",
    "heroku.com",
    "kubernetes.io",
    "docker.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",

    # -- Services Web, visio, etc. --
    "zoom.us",
    "slack.com",
    "teams.microsoft.com",
    "webex.com",

    # -- Paiements & banques (exemples) --
    "paypal.com",
    "stripe.com",
    # Tu peux ajouter des banques ou fintechs locales

    # -- Services publics ou gouvernementaux (ex. France) --
    "ameli.fr",  
    "impots.gouv.fr",

    # -- Autres importants selon le contexte --
    "oracle.com",
    "ibm.com",
    "adobe.com",
    # ...
]
    "microsoft.com",
    "amazon.com",
    "cloudflare.com",
    "ameli.fr"
    
]

# TRecord we want to gather
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT", "NS"]

# ES' address
ES_URL = "http://localhost:9200"

# Index hame
ES_INDEX = "passivedns"

# ES config

es = Elasticsearch(ES_URL)

# check or creating indexes
if not es.indices.exists(index=ES_INDEX):
    mapping = {
        "mappings": {
            "properties": {
                "domain":       {"type": "keyword"},
                "timestamp":    {"type": "date"},
                "record_type":  {"type": "keyword"},
                "record_value": {"type": "keyword"},
                "source":       {"type": "keyword"}
            }
        }
    }
    es.indices.create(index=ES_INDEX, body=mapping)
    print(f"[+] Index '{ES_INDEX}' créé dans Elasticsearch.")


# Resolving function to collect DNS records

def resolve_dns(domain: str):

    results = []
    for rtype in DNS_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            for rdata in answers:

                results.append((rtype, str(rdata)))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass
        except Exception as e:

            pass
    return results

# storing DNS records resolved in ES
def store_dns_records(domain: str, dns_records, source="unknown"):
 
    timestamp = datetime.utcnow().isoformat()

    for (rtype, rvalue) in dns_records:
        doc = {
            "domain": domain,
            "timestamp": timestamp,
            "record_type": rtype,
            "record_value": rvalue,
            "source": source
        }
        es.index(index=ES_INDEX, body=doc)
    if dns_records:
        print(f"[+] Enregistré {len(dns_records)} enregistrements DNS pour '{domain}' (source={source}).")


# using DNS twist to identify typosquatting

def run_dnstwist(domain: str):

    command = ["dnstwist", "--registered", "--format", "json", domain]
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=60)
        data = json.loads(output)
    except subprocess.TimeoutExpired:
        print(f"[!] dnstwist timeout pour {domain}")
        return []
    except subprocess.CalledProcessError as e:
        print(f"[!] dnstwist erreur CalledProcessError: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"[!] dnstwist - impossible de parser la sortie JSON : {e}")
        return []


    permutations = []
    for entry in data:

        if entry.get("dns_a"):
            permutations.append(entry["domain"])

    return permutations

# Processing data gathered by dnstwist in the resolving function
def process_brand_domains():

    for domain in BRAND_DOMAINS:
        print(f"[*] Vérification dnstwist sur domaine sensible : {domain}")
        permutations = run_dnstwist(domain)
        print(f"[+] {len(permutations)} permutations actives trouvées pour {domain}.")


        for perm_domain in permutations:
            dns_records = resolve_dns(perm_domain)
            store_dns_records(perm_domain, dns_records, source="dnstwist")


# Processing of certstream data
def process_certstream_message(message, context):

    data = message.get("data", {})
    leaf_cert = data.get("leaf_cert", {})
    all_domains = leaf_cert.get("all_domains", [])

    for domain in all_domains:
        
        domain = domain.lower().lstrip("*.")
        
        if "." not in domain or len(domain) < 4:
            continue

        
        dns_records = resolve_dns(domain)
        store_dns_records(domain, dns_records, source="certstream")

#listener to certstream flow

def start_certstream_listener():

    import ssl
    print("[*] Connexion à CertStream...")
    certstream.listen_for_events(process_certstream_message, url='wss://certstream.calidog.io/')


# Main function
if __name__ == "__main__":
    import threading


    print("[*] Scan initial des domaines 'sensibles' via dnstwist...")
    #process_brand_domains()

    # separate thread for certstream
    certstream_thread = threading.Thread(target=start_certstream_listener, daemon=True)
    certstream_thread.start()

    print("[*] Écoute CertStream lancée (thread). Presse Ctrl+C pour quitter.")

    # main loop
    try:
        while True:
            time.sleep(30)

    except KeyboardInterrupt:
        print("[!] Arrêt sur interruption utilisateur.")
