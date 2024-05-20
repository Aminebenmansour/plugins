import telnetlib
import os
from autorecon.plugins import ServiceScan

class POP3Audit(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "POP3 Audit"
        self.tags = ['default','unsafe', 'pop3']

    def configure(self):
        self.match_service_name('^pop3')

    async def run(self, service):
        print('amine')
        if service.protocol == 'tcp':
            result = await self.run_pop3_audit(service.target.address, service.port)
            print("Résultats de l'audit POP3 :", result)
            await self.save_audit_results(service, result)

    async def run_pop3_audit(self, target_ip, port):
        try:
            # Connexion au serveur POP3
            tn = telnetlib.Telnet(target_ip, port, timeout=10)
            print('amine',tn)
            
            # Attendre la réponse initiale du serveur
            response = tn.read_until(b'\n', timeout=10).decode('utf-8')
            print('rr',response)
            output = response

            # Envoyer une commande POP3
            tn.write(b'USER username\r\n')
            response = tn.read_until(b'\n', timeout=10).decode('utf-8')
            output += response

            # Envoyer une autre commande POP3
            tn.write(b'PASS password\r\n')
            response = tn.read_until(b'\n', timeout=10).decode('utf-8')
            output += response

            # Fermer la connexion
            tn.close()

            return output

        except ConnectionRefusedError:
            return "La connexion a été refusée. Assurez-vous que le serveur POP3 est accessible."
        except TimeoutError:
            return "La connexion a expiré. Vérifiez votre connexion réseau."

    async def save_audit_results(self, service, result):
        scandir = service.target.scandir
        filename = f"pop3_audit_results_port_{service.port}.txt"
        filepath = os.path.join(scandir, filename)

        with open(filepath, "w") as f:
            f.write(result)

        print(f"Les résultats de l'audit POP3 ont été enregistrés dans : {filepath}")

# Exemple d'utilisation
# pop3_audit = POP3Audit()
# await pop3_audit.run(service)

