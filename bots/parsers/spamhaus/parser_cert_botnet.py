# -*- coding: utf-8 -*-
"""
Header of the File:
; For questions on the Spamhaus Botnet C&C List, please refer to www.spamhaus.org/bgpf
; Prepared for CERTUNLP on UTC = Fri Aug 14 19:01:21 2020
; Copyright 2020 Spamhaus.  Botnet C&C Listing:
;
"""

from intelmq.lib.bot import ParserBot
from intelmq.lib.harmonization import DateTime

__all__ = ['SpamhausCERTBotnetParserBot']


class SpamhausCERTBotnetParserBot(ParserBot):
    """Spamhaus spam web report parser"""

    def parse_line(self, row, report):
        if not len(row) or row.startswith(';'):
            self.tempdata.append(row)
        else:
            row_splitted = [field.strip() for field in row.strip().split(',')]
            event = self.new_event(report)

            event.add('source.ip', row_splitted[1])
            source_asn = row_splitted[2].replace('AS', '')
            if source_asn != '?':
                event.add('source.asn', source_asn)
            event.add('extra.sbl', row_splitted[0])
            event.add('extra.asn.name', row_splitted[3])
            event.add('extra.botnet.description', row_splitted[4])
            event.add('classification.type', 'c2server')
            event.add('classification.taxonomy', 'malicious code')
            event.add('raw', self.recover_line(row))
            self.logger.info("Esto se esta ejecutando y anda")
            yield event


BOT = SpamhausCERTBotnetParserBot
