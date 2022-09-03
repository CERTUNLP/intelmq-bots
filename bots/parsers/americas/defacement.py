# -*- coding: utf-8 -*-
"""
Americas Defacecment (ZoneH) CSV defacement report parser
"""
from urllib.parse import urlparse

from intelmq.lib.bot import ParserBot


class AmericasDefacementParserBot(ParserBot):
    """Americas Defacecment (ZoneH) CSV defacement report parser"""
    ignore_lines_starting = [
        'CSIRTAmericas Observation time']
    recover_line = ParserBot.recover_line
    parse = ParserBot.parse_csv

    def parse_line(self, row, report):
        event = self.new_event(report)
        # header = "add_date,attacker,domain,ip_address,system,web_server,reason,hackmode,image,type,redefacement,state,def_grade,defacement_id"
        header = "CSIRTAmericas Observation time,Zoneh add date,Attacker,Domain,IP Address,ASN,AS Name,System,Web Server,Reason,Hackmode,Mirror,Type,Redefacement,Publication,Def Grade,Defacement ID,Taxonomy,Provider"
        hf = header.split(',')
        parsed_url = urlparse(row[hf.index('Domain')])
        event.add('classification.identifier', "defacement")
        event.add('classification.type', 'defacement')
        event.add('event_description.text', 'compromised website')

        # self.logger.info('CSV to parse: {}'.format(row))

        event.add('raw', "{}\n{}".format(header, self.current_line))
        event.add('time.source', row[hf.index('Zoneh add date')] + ' UTC')
        event.add("extra.actor", row[hf.index('Attacker')])
        event.add('source.fqdn', parsed_url.netloc, raise_failure=False)
        event.add('protocol.application', parsed_url.scheme)
        event.add('source.url', row[hf.index('Domain')], raise_failure=False)
        event.add('source.ip', row[hf.index(
            'IP Address')], raise_failure=False)
        event.add("extra.os.name", row[hf.index('System')])
        event.add("extra.http_target", row[hf.index('Web Server')])
        event.add("extra.reason", row[hf.index('Reason')])
        event.add("extra.compromise_method", row[hf.index('Hackmode')])
        # event.add("extra.image", row[hf.index('image')])
        event.add("extra.type", row[hf.index('Type')])
        event.add("extra.redefacement", row[hf.index('Redefacement')])
        # event.add("extra.state", row[hf.index('state')])
        event.add("extra.def_grade", row[hf.index('Def Grade')])
        event.add("extra.zoneh_report_id", row[hf.index('Defacement ID')])
        yield event


BOT = AmericasDefacementParserBot
