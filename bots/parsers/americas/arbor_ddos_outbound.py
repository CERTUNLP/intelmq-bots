# -*- coding: utf-8 -*-
"""
Americas Arbor DDoS Outbound CSV defacement report parser

Header:
Start, End, Source CIDR, Source ASN, Source CC, Max BPS, Max PPS
"""
from urllib.parse import urlparse

from intelmq.lib.bot import ParserBot


class AmericasArborDdosOutboundParserBot(ParserBot):
    """Americas Arbor DDoS Outbound CSV defacement report parser"""
    ignore_lines_starting = [
        'OBSERVED OUTBOUND ATTACKS', 'Based on actual alerts']
    recover_line = ParserBot.recover_line
    parse = ParserBot.parse_csv_dict

    def parse_line(self, row, report):
        event = self.new_event(report)
        header = 'Start,End,DestCIDR,DestASN,DestCC,MaxBPS,MaxPPS'
        self.logger.info('CSV to parse: {}'.format(row))

        event.add('classification.identifier', "amplification-ddos-victim")
        event.add('classification.type', 'ddos')
        event.add('event_description.text', 'ddos-outbound')

        event.add('raw', "{}\n{}".format(header, self.current_line))
        event.add("source.geolocation.cc",
                  row[' Source CC'], raise_failure=False)
        event.add('time.source', row['Start'] + ' UTC')
        event.add("source.asn", row[' Source ASN'])
        event.add('source.ip', row[' Source CIDR'], raise_failure=False)
        event.add("extra.start", row['Start'])
        event.add("extra.end", row[' End'])
        event.add("extra.maxbps", row[' Max BPS'])
        event.add("extra.maxpps", row[' Max PPS'])

        yield event


BOT = AmericasArborDdosOutboundParserBot
