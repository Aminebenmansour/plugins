from autorecon.plugins import ServiceScan
import requests
import subprocess
import os
import colorama
import re

class HTTPBackdoor(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "HTTP Backdoor"
        self.tags = ['default', 'unsafe', 'http']

    def configure(self):
        self.match_service_name('^http')

    async def run(self, service):
        if service.protocol == 'tcp':
            # Envoi d'une requête HTTP pour récupérer les en-têtes de réponse
            response = await self.send_http_request(service)
            print("En-têtes de réponse HTTP:", response.headers)

            # Vérification de la présence de l'en-tête "X-Powered-By"
            if 'X-Powered-By' in response.headers:
                x_powered_by = response.headers['X-Powered-By']
                print(f"Vulnérabilité détectée : X-Powered-By ({x_powered_by})")
                await self.install_reverse_shell(service, x_powered_by)

    async def send_http_request(self, service):
        url = f"http://{service.target.address}:{service.port}/"
        return requests.get(url)
    async def install_reverse_shell(self, service, x_powered_by):
        # Remplacer '/' par un espace dans x_powered_by
        x_powered_by = x_powered_by.replace('/', ' ')
        
        # Recherche d'exploits correspondant à x_powered_by
        exploit_results = await self.search_exploits(x_powered_by)
        print("Exploit results:", exploit_results)
        scandir = os.path.join(service.target.scandir, service.protocol + str(service.port))
        print('sc',scandir)
        # Créer le chemin complet pour le fichier exploit_results.txt
        exploit_results_file = os.path.join(scandir, "exploit_results.txt")

        # Écrire les résultats dans le fichier
        with open(exploit_results_file, "w") as f:
            if exploit_results:
                print(exploit_results)
                for key, value in exploit_results.items():
                     key_value_line = "{}: {}".format(key, value.strip())
                     if key_value_line:
                        f.write("Exploit line: {}\n".format(key_value_line))
                     else:
                        f.write("Aucun exploit trouvé pour cette vulnérabilité.\n")
            else:
                f.write("Aucun exploit trouvé pour cette vulnérabilité.\n")

        print("Les résultats de la recherche d'exploits ont été enregistrés dans", exploit_results_file)



    async def search_exploits(self, x_powered_by):
        # Recherche d'exploits avec searchsploit pour x_powered_by
        print(x_powered_by)
        search_term = f"{x_powered_by}"
        command = ['searchsploit', search_term]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = process.communicate()
        
        # Nettoyer la sortie de la commande des caractères de contrôle ANSI
        stdout_clean = re.sub(r'\x1b\[[0-9;]*[mGK]', '', stdout)
        exploit_lines = stdout_clean.strip().split('\n')
        print('rrr', len(exploit_lines))
        filtered_exploits = {}
        for line in exploit_lines:
            t = line.split('|')
            if len(t) >= 2 and  x_powered_by in t[0] :
                filtered_exploits[t[0]] = t[1]

        # Filtrer les résultats pour ne garder que les exploits dont le titre commence par "xpowred"
        
        return filtered_exploits