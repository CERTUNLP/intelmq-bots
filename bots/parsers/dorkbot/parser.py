# -*- coding: utf-8 -*-
"""
Dorkbot report parser

Header:
Start, End, Source CIDR, Source ASN, Source CC, Max BPS, Max PPS
"""
from urllib.parse import urlparse

from intelmq.lib.bot import ParserBot
from intelmq.lib import utils
from xml.etree import ElementTree as ET
import re

class DorkbotParserBot(ParserBot):
    """Dorkbot report parser"""
    def process(self):
        report = self.receive_message()
#        self.logger.info(report.get("raw"))
        peek = utils.base64_decode(report.get("raw"))

        em = report.get("extra.email_subject")
        event = self.new_event(report)
        event.add('extra.dorkbotid', re.findall(r'\d+', em)[0])
        event.add('classification.type', 'compromised')
        event.add('raw', peek)


        root = ET.fromstring(peek)
        for child in root:
            if child.tag == "ipaddress":
                event.add('source.ip', child.text)
            if child.tag == "poc":
                event.add('extra.poc', child.text)
            if child.tag == "issue":
                event.add('extra.issue', child.text)
            if child.tag == "type":
                if "xss" in child.text:
                    event.add('classification.identifier', "xss")
                elif "sql" in child.text:
                    event.add('classification.identifier', "sql_injection")
                else:
                    event.add('classification.identifier', child.text)

        self.send_message(event)
        self.acknowledge_message()


BOT = DorkbotParserBot

