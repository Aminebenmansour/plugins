import os
import re
from semiautorecon.plugins import ServiceScan
import subprocess

class HTTPBackdoor(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "HTTP version Backdoor"
        self.tags = ['default', 'unsafe', 'http']

    def configure(self):
        self.match_service_name('^http')

    async def run(self, service):
        if service.protocol == 'tcp':
            version = self.get_http_version(service.target.scandir)
            print("Version du service HTTP:", version)
            await self.search_and_save_exploits(service, version)

    def get_http_version(self, scandir):
        # Chemin du fichier _full_tcp_nmap.txt
        nmap_file = os.path.join(scandir, "_full_tcp_nmap.txt")

        # Vérifier si le fichier existe
        if os.path.exists(nmap_file):
            with open(nmap_file, "r") as f:
                # Lire le contenu du fichier ligne par ligne
                for line in f:
                    # Rechercher la ligne qui contient les informations sur la version du service HTTP
                    if "80/tcp" in line.lower():
                        print('aa',line)
                        # Extraire la version du service HTTP de la ligne
                        version = line.split()[4]
                        if isinstance(version, list):
                            version = ' '.join(version)
                        print('ee',version)
                        return version  # Retourner la version trouvée

        # Si la version n'a pas été trouvée ou si le fichier nmap n'existe pas, retourner une version par défaut
        print(f"Version du service HTTP non trouvée dans {nmap_file}")
        return "Version non disponible"

    async def search_and_save_exploits(self, service, version):
        # Recherche d'exploits pour la version du service HTTP
        search_term = f"{version}"
        command = ['searchsploit', search_term]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = process.communicate()
        
        # Nettoyer la sortie de la commande des caractères de contrôle ANSI
        stdout_clean = re.sub(r'\x1b\[[0-9;]*[mGK]', '', stdout)
        print(stdout_clean)
        exploit_lines = stdout_clean.strip().split('\n')
        
        # Enregistrement des résultats d'exploits dans un fichier
        scandir = os.path.join(service.target.scandir, service.protocol + str(service.port))
        exploit_results_file = os.path.join(scandir, "http_exploit_results.txt")

        with open(exploit_results_file, "w") as f:
            if exploit_lines:
                for line in exploit_lines:
                    f.write(line + "\n")
            else:
                f.write("Aucun exploit trouvé pour cette version de HTTP.\n")

        print("Les résultats de la recherche d'exploits HTTP ont été enregistrés dans", exploit_results_file)

