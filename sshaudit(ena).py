import os
import re
import subprocess
from semiautorecon.plugins import ServiceScan

class SSHAudit(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "SSH Audit"
        self.tags = ['default', 'safe', 'ssh']

    def configure(self):
        self.match_service_name('^ssh')

    async def run(self, service):
        if service.protocol == 'tcp':
            result = self.run_ssh_audit(service.target.address, service.port)
            print("Résultats de l'audit SSH :", result)
            await self.save_audit_results(service, result)

    def run_ssh_audit(self, target_ip, port):
        try:
            # Exécuter ssh-audit avec l'adresse IP et le numéro de port du serveur SSH
            result = subprocess.run(['ssh-audit', f'{target_ip}'], capture_output=True, text=True)

            # Récupérer la sortie de la commande ssh-audit
            output = result.stdout

            # Nettoyer les codes de couleur ANSI
            clean_output = self.remove_ansi_escape_sequences(output)

            return clean_output

        except subprocess.CalledProcessError as e:
            # En cas d'erreur lors de l'exécution de ssh-audit
            return f"Erreur lors de l'exécution de ssh-audit : {e.stderr}"

    def remove_ansi_escape_sequences(self, text):
        # Expression régulière pour les codes de couleur ANSI
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

        # Remplacer les codes de couleur ANSI par une chaîne vide
        clean_text = ansi_escape.sub('', text)

        return clean_text

    async def save_audit_results(self, service, result):
        scandir = service.target.scandir+service.protocol+str(service.port)
        filename = f"ssh_audit_results_port_{service.port}.txt"
        filepath = os.path.join(scandir, filename)

        with open(filepath, "w") as f:
            f.write(result)

        print(f"Les résultats de l'audit SSH ont été enregistrés dans : {filepath}")

