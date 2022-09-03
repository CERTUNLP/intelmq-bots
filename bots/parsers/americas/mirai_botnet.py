# -*- coding: utf-8 -*-
"""
Americas Mirai Botnet CSV defacement report parser

Header:
ip address,autonomous system,country,asn,date first seen

'/botnets/badpackets/Mirai_botnet/'
'{0}-miraiBotNet-%s.csv'
"""
from urllib.parse import urlparse

from intelmq.lib.bot import ParserBot
from intelmq.lib.exceptions import InvalidValue


class AmericasMiraiBotnetParserBot(ParserBot):
    """Americas Mirai Botnet CSV defacement report parser"""
    recover_line = ParserBot.recover_line
    parse = ParserBot.parse_csv_dict

    def parse_line(self, row, report):
        event = self.new_event(report)
        header = 'ip address,autonomous system,country,asn,date first seen'
        self.logger.info('CSV to parse: {}'.format(row))

        event.add('classification.identifier', "mirai-botnet")
        event.add('classification.type', 'infected-system')
        event.add('event_description.text', 'mirai-botnet')

        event.add('raw', "{}\n{}".format(header, self.current_line))
        event.add('time.source', row['date first seen'])
        event.add("source.geolocation.cc",
                  row['country'], raise_failure=False)
        try:
            event.add("source.asn", row['asn'])
            event.add("extra.asn.name", row['autonomous system'])
        except InvalidValue:
            self.logger.info("ASN Not valid. ASN:{} AS:{}.".format(row['asn'], row['autonomous system']))
        
        event.add('source.ip', row['ip address'], raise_failure=False)

        yield event


BOT = AmericasMiraiBotnetParserBot
