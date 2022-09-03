# -*- coding: utf-8 -*-
"""
CMD parser
"""
from urllib.parse import urlparse
from subprocess import check_output, PIPE, Popen, STDOUT
# from shlex import split

from intelmq.lib import utils
from intelmq.lib.bot import ParserBot


class CMDParserBot(ParserBot):
    """CMD Parser Bot"""
    cmd: str = "<command>"

    recover_line = ParserBot.recover_line

    def process(self):
        report = self.receive_message()
        event = self.new_event(report)
        raw_report = utils.base64_decode(report["raw"])
        self.logger.info("raw: {}".format(raw_report))

        self.logger.info("open process")
        p = Popen(self.cmd,
                  stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)

        output, error = p.communicate(input=raw_report.encode('utf-8'))
        self.logger.info(
            "doing comunicating return_code: {}".format(p.returncode))
        self.logger.info("doing comunicating stderr: {}".format(error))
        self.logger.info("doing comunicating stdout: {}".format(output))

        if p.returncode == 0:
            self.logger.info("Sending to next process")
            event.add('raw', output)
            self.send_message(event)
        else:
            self.logger.error("doing comunicating stderr: {}".format(error))

        self.acknowledge_message()


BOT = CMDParserBot
