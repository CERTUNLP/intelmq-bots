# -*- coding: utf-8 -*-
"""
Americas Mirai Botnet CSV defacement report parser

Header:
phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target

'/phishing_and_spam/phishtank/phishingDomains/'
'{0}-phishTank-%s.csv'
"""
from urllib.parse import urlparse

from intelmq.lib.bot import ParserBot


class AmericasPhishtankDomainsParserBot(ParserBot):
    """Americas Mirai Botnet CSV defacement report parser"""
    recover_line = ParserBot.recover_line
    parse = ParserBot.parse_csv_dict

    def parse_line(self, row, report):
        event = self.new_event(report)
        header = 'phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target'
        self.logger.info('CSV to parse: {}'.format(row))
        parsed_url = urlparse(row['url'])

        event.add('classification.identifier', "phishing-website")
        event.add('classification.type', 'phishing')
        event.add('event_description.text', 'phishing')

        event.add('raw', "{}\n{}".format(header, self.current_line))
        event.add('time.source', row['submission_time'] + ' UTC')
        event.add('source.fqdn', parsed_url.netloc, raise_failure=False)
        event.add('protocol.application', parsed_url.scheme)
        event.add('source.url', row['url'], raise_failure=False)
        event.add("extra.target", row['target'])
        event.add("extra.online", row['online'])
        event.add("extra.verification_time", row['verification_time'])
        event.add("extra.verified", row['verified'])
        event.add("extra.phish_detail_url", row['phish_detail_url'])
        event.add("extra.phishtank_id", row['phish_id'])

        yield event


BOT = AmericasPhishtankDomainsParserBot
