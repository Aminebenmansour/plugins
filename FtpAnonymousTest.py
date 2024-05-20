from autorecon.plugins import ServiceScan

class FtpAnonymousTest(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "FTP Anonymous Test"
        self.tags = ['default', 'safe', 'ftp']

    def configure(self):
        self.match_service_name('^ftp')

    async def run(self, service):
        if service.protocol == 'tcp':
            # Utilisation de la commande ftp pour vérifier l'accès anonyme
            await service.execute('ftp -n {addressv4} {port} <<END\nuser anonymous anonymous\nls\nquit\nEND', outfile='{protocol}_{port}_ftp_anonymous_test.txt')

