# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import fnmatch
import ntpath
from datetime import datetime, timedelta
from . import ftp_helper
from intelmq.lib.bot import CollectorBot
from intelmq.lib.exceptions import InvalidArgument


class Time(object):
    def __init__(self, delta=None):
        """ Delta is a datetime.timedelta JSON string, ex: '{days=-1}'. """
        self.time = datetime.now()
        if not isinstance(delta, bool):
            self.time += timedelta(**delta)

    def __getitem__(self, timeformat):
        return self.time.strftime(timeformat)


class FTPCollectorBot(CollectorBot):
    """ FTP Bot collerctor """
    ftp_tls: bool = False
    ftp_host: str = "<host>"
    ftp_username: str = ""
    ftp_password: str = ""
    ftp_file_path: str = "<filepath>"
    ftp_file_path_formatting: bool = False
    regex_file_name: bool = False

    def init(self):
        super().init()
        if self.ftp_file_path is None:
            raise InvalidArgument('ftp_file_path', expected='string')

    def process(self):
        self.logger.info(f"Downloading report from {self.ftp_host}.")
        self.logger.info("Connecting to FTP...")

        ftp = ftp_helper.FTPHelper()
        if self.ftp_tls and self.ftp_tls:
            ftp.connect_tls(self.ftp_host)
        else:
            ftp.connect(self.ftp_host)
        self.logger.info("Connected to FTP.")

        if self.ftp_username and self.ftp_password:
            ftp.login(self.ftp_username,
                      self.ftp_password)
        self.logger.info("Logged to FTP.")

        formatting = self.ftp_file_path_formatting
        if formatting:
            try:
                ftp_file_path = self.ftp_file_path.format(time=Time(formatting))
            except TypeError:
                self.logger.error(f"Wrongly formatted ftp_file_path_formatting parameter: {formatting}. Should be boolean or a time-delta JSON.")
                raise
            except KeyError:
                self.logger.error(f"Wrongly formatted ftp_file_path parameter: {self.ftp_file_path}. Possible misspell with 'time' variable.")
                raise
        else:
            ftp_file_path = self.ftp_file_path

        self.logger.info(f"File to retrieve: {ftp_file_path}")
        path, file_name = ntpath.split(ftp_file_path)
        
        list_files = [file_name]
        
        if self.regex_file_name:
            if not file_name:
                file_name = '*'

            try:
                ls = ftp.ls(path)
            except ftp_helper.FTPDirDoesNotExistsException as e:
                self.logger.error(e.errors)
                raise e

            self.logger.info(f"Dirs found in folder: {ls[0]}.")
            self.logger.info(f"Files found in folder: {ls[1]}.")

            file_names = [f_data[-1] for f_data in ls[1]]

            list_files = fnmatch.filter(file_names, file_name)
            self.logger.info(f"Files matched: {list_files}")

        for fname in list_files:
            try:
                data_file = ftp.get_data_file(path, fname)
                self.logger.info("Report data downloaded retrieved.")

                report = self.new_report()
                report.add("raw", data_file)
                report.add("feed.url", f'ftp://{self.ftp_host}')
                report.add("extra.file_path", ftp_file_path)
                self.send_message(report)
            except ftp_helper.FTPFileNotFoundException as e:
                self.logger.warn(e.errors)


BOT = FTPCollectorBot
