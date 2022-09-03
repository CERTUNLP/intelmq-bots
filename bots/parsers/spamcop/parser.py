# -*- coding: utf-8 -*-
"""
Spamcop mail spam report parser

"""
from urllib.parse import urlparse

from intelmq.lib.bot import ParserBot
from intelmq.lib import utils
import re


class SpamcopParserBot(ParserBot):
    """Spamcop mail spam report parser"""

    def process(self):
        report = self.receive_message()
        #        self.logger.info(report.get("raw"))
        peek = utils.base64_decode(report.get("raw"))
        em = report.get("extra.email_subject")

        event = self.new_event(report)
        event.add('extra.spamcopid', re.findall(r':(.*?)]', em)[0])
        event.add('source.ip', re.findall(r'\((.*?)\)', em)[0])
        event.add('classification.type', 'spam')
        event.add('classification.taxonomy', 'abusive content')
        event.add('raw', peek.split("Offending message ]\r\n")[1])

        self.send_message(event)
        self.acknowledge_message()


BOT = SpamcopParserBot
