import ftplib

class FTPHelper():
    ftp = None

    class Reader:
        def __init__(self):
            self.data = b""

        def __call__(self, data):
            self.data += data

    def get_data_file(self, path, file):
        r = self.Reader()
        self.cwd(path)
        try:
            self.ftp.retrbinary("RETR {}".format(file), r)
        except ftplib.error_perm as e:
            raise FTPFileNotFoundException('{} {} path:"{}" file:"{}"'.format(
                'FTP', str(e), path, file))

        return r.data.decode('utf-8')

    def ls(self, path):
        ls = []
        dirs = []
        files = []
        self.cwd(path)
        self.ftp.retrlines('LIST', ls.append)
        for line in ls:
            if line[0] == 'd':
                dirs.append(line.split())
            else:
                files.append(line.split())

        return dirs, files
    
    def cwd(self, path):
        try:
            self.ftp.cwd(path)
        except ftplib.error_perm as e:
            raise FTPDirDoesNotExistsException('{} {} path:"{}"'.format(
                'FTP', str(e), path))

    def connect(self, server):
        self.ftp = ftplib.FTP(server, timeout=60)

    def connect_tls(self, server):
        self.ftp = ftplib.FTP(server, timeout=60)

    def login(self, username, password):
        self.ftp.login(username, password)

    def quit(self):
        self.ftp.quit()

class FTPDirDoesNotExistsException(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)
        self.errors = "Directory does not exists. {}".format(message)

class FTPFileNotFoundException(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)
        self.errors = "File not found. {}".format(message)