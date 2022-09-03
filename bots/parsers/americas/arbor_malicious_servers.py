# -*- coding: utf-8 -*-
"""
Americas Arbor Malicious Servers CSV defacement report parser

Header:
CC, ASN, IP, port, malware MD5

 '/botnets/arbor/malicious_servers/'
 '{0}-malicious_servers-%s.csv'
"""
from urllib.parse import urlparse

from intelmq.lib.bot import ParserBot


class AmericasArborMaliciousServersParserBot(ParserBot):
    """Americas Arbor Malicious Servers CSV defacement report parser"""
    ignore_lines_starting = [
        'MALICIOUS SERVERS', 'Botnet C&C Servers', 'Based on malicious software analysis and botnet tracking.']
    recover_line = ParserBot.recover_line
    parse = ParserBot.parse_csv_dict

    def parse_line(self, row, report):
        event = self.new_event(report)
        self.logger.info('CSV to parse: {}'.format(row))

        #event.add('classification.identifier', "amplification-ddos-victim")
        event.add('classification.type', 'malware')
        event.add('event_description.text', 'malware')

        event.add('raw', self.recover_line(self.current_line))
        event.add("source.geolocation.cc",
                  row['CC'], raise_failure=False)
        event.add("source.asn", row[' ASN'])
        event.add('source.ip', row[' IP'], raise_failure=False)
        event.add('source.port', row[' port'], raise_failure=False)
        event.add("extra.malware", row[' malware MD5'])

        yield event


BOT = AmericasArborMaliciousServersParserBot
