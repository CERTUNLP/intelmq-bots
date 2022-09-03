# -*- coding: utf-8 -*-
"""
Spampot CSV malware report parser

Header:
#date;ip;cidr;asn;cc;emails;rcpts;conns;http;smtp;submission;socks4;socks4a;socks5
"""
from urllib.parse import urlparse

from intelmq.lib.bot import ParserBot


class SpampotParserBot(ParserBot):
    """Spampot mail spam report parser"""
    ignore_lines_starting = [
        '#CC', '#date;ip;cidr;asn;cc;emails;rcpts;conns;http;smtp;submission;socks4;socks4a;socks5']
    recover_line = ParserBot.recover_line
    parse = ParserBot.parse_csv

    def parse_line(self, row, report):
        event = self.new_event(report)
        header = 'date,ip,cidr,asn,cc,emails,rcpts,conns,http,smtp,submission,socks4,socks4a,socks5'
        hf = header.split(',')
        row = self.current_line.split('\n')[0].split(';')
        self.logger.info('CSV to parse: {}'.format(row))

        # event.add('classification.identifier', "amplification-ddos-victim")
        event.add('classification.type', 'malware')
        event.add('event_description.text', 'malware')

        event.add('raw', "{}\n{}".format(header, ','.join(row)))
        event.add('time.source', row[hf.index('date')])
        event.add("source.geolocation.cc",
                  row[hf.index('cc')], raise_failure=False)
        event.add('source.ip', row[hf.index('ip')], raise_failure=False)
        event.add("source.asn", row[hf.index('asn')], raise_failure=False)
        event.add('extra.cidr', row[hf.index('cidr')])
        event.add("extra.emails", row[hf.index('emails')])
        event.add("extra.rcpts", row[hf.index('rcpts')])
        event.add("extra.conns", row[hf.index('conns')])
        event.add("extra.http", row[hf.index('http')])
        event.add("extra.smpt", row[hf.index('smtp')])
        event.add("extra.submission", row[hf.index('submission')])
        event.add("extra.socks4", row[hf.index('socks4')])
        event.add("extra.socks4a", row[hf.index('socks4a')])
        event.add("extra.socks5", row[hf.index('socks5')])

        yield event


BOT = SpampotParserBot
