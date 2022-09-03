# -*- coding: utf-8 -*-
"""
Americas Arbor Observerd Attack Commands CSV defacement report parser

Header:
Timestamp, C&C CC, C&C ASN, C&C IP, Target CC, Target ASN, Target IP

 '/botnets/arbor/observed_attack_commands/'
 '{0}-observed_attack_commands-%s.csv'
"""
from urllib.parse import urlparse

from intelmq.lib.bot import ParserBot


class AmericasObservedAttackCommandsParserBot(ParserBot):
    """Americas Arbor Observerd Attack Commands CSV defacement report parser"""
    ignore_lines_starting = [
        'OBSERVED ATTACK COMMANDS', 'Based on botnet tracking']
    recover_line = ParserBot.recover_line
    parse = ParserBot.parse_csv_dict

    def parse_line(self, row, report):
        event = self.new_event(report)
        header = 'Timestamp,C&C CC,C&C ASN,C&C IP,Target CC,Target ASN,Target IP'
        self.logger.info('CSV to parse: {}'.format(row))

        #event.add('classification.identifier', "amplification-ddos-victim")
        event.add('classification.type', 'malware')
        event.add('event_description.text', 'malware')

        event.add('raw', "{}\n{}".format(header, self.current_line))
        event.add("source.geolocation.cc",
                  row[' C&C CC'], raise_failure=False)
        event.add("source.asn", row[' C&C ASN'])
        event.add('source.ip', row[' C&C IP'], raise_failure=False)
        event.add("destination.geolocation.cc",
                  row[' Target CC'], raise_failure=False)
        event.add("destination.asn", row[' Target ASN'])
        event.add('destination.ip', row[' Target IP'], raise_failure=False)

        yield event


BOT = AmericasObservedAttackCommandsParserBot
