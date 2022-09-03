# -*- coding: utf-8 -*-

import intelmq.lib.utils as utils
import base64
from pyngen import PyNgen
from pyngen.ngen_exceptions import NewIncidentTypeDeactivatedError
from intelmq.lib.bot import OutputBot
import json
import traceback


class RestAPINgenOutputBot(OutputBot):
    timeout: int = 10
    create_type: bool = False
    stop_on_error: bool = True
    retries: int = 5
    host: str = "<ngen_api_url>"
    auth_token: str = "<auth_token>"

    def init(self):
        # TODO: add proxy configuration in pyngen
        self.ngen = PyNgen(self.host, self.auth_token, timeout=self.timeout)
        
    def process(self):
        event = self.receive_message()
        event_dict = event.to_dict(hierarchical=False)
        event_dict.pop("feed.url", None)
        self.logger.info("{}".format(event_dict))
        address = event_dict.get("source.fqdn",  # try first by fqdn
                                 event_dict.get("source.ip", None))  # else by ip
        if not address:
            self.logger.warn("No source address found in event, trying with network.")
            address = event_dict.get("source.network", None)
            if not address:
                self.logger.error("No source address found in event, skipping.")
            else:
                address = address.split("/")[0] # remove subnet mask if present, until ngen supports it
        incident_feed = event_dict['feed.provider'].lower()

        evidence = json.dumps(event_dict, indent=4)

        if 'extra.ngen.type' in event_dict:
            incident_type = event_dict['extra.ngen.type'].lower()
        else:
            if "classification.identifier" in event_dict.keys():
                incident_type = event_dict['classification.identifier'].replace(
                    ' ', '_').replace('-', '_').lower()

                self.logger.warn(
                    'Event has no attribute extra.ngen.type, used instead \
                        classification.identifier replacing spaces and score by underscore: {}.'.format(incident_type))
            elif "classification.taxonomy" in event_dict.keys():
                incident_type = event_dict['classification.taxonomy'].replace(
                    ' ', '_').replace('-', '_').lower()

                self.logger.warn(
                    'Event has no attribute extra.ngen.type or classification.identifier, used instead \
                        classification.taxonomy replacing spaces and score by underscore: {}.'.format(incident_type))
            else:
                msg = "Event has no attribute extra.ngen.type or classification.identifier or classification.taxonomy\n{}".format(evidence)
                self.logger.error(msg)
                raise Exception(msg)
            self.logger.info("Sending: address: {}, feed: {}, type: {}.".format(address, incident_feed, incident_type))

        counter = self.retries
        while counter != 0:
            counter -= 1
            try:
                self.ngen.newIncident(address,
                                    incident_feed,
                                    incident_type,
                                    evidence_text=utils.base64_decode(event_dict['raw']),
                                    raw=evidence,
                                    create_type=self.create_type)
                self.logger.info('Message sent.')
                break
            except NewIncidentTypeDeactivatedError:
                self.logger.warn("Type {} is deactivated in Ngen so incident can't be created.\n\nAddress: {} - Feed: {} - Type: {}\n\nJson:\n{}".format(incident_type, address, incident_feed, incident_type, evidence))
                if self.stop_on_deactivated:
                    self.logger.info("Stop on deactivated is true. Bot is going to stop...")
                    self.logger.error("BOT STOPPED! Stop on deactivated is true.\n\nNgen responses:\n{}\n\nComplete traceback:\n{}\n\nAddress: {} - Feed: {} - Type: {}\n\nJson:\n{}".format(e, tb, address, incident_feed, incident_type, evidence))
                    self.stop()
                else:
                    self.logger.info("Stop on deactivated is false. Bot will pop next item...")
                    break
            except Exception as e:
                tb = traceback.format_exc()
                self.logger.warn("Error. {} tries left of {}.\n\nNgen responses:\n{}\n\nComplete traceback:\n{}\n\nAddress: {} - Feed: {} - Type: {}\n\nJson:\n{}".format(counter, self.retries, e, tb, address, incident_feed, incident_type, evidence))
                if counter == 0 and self.stop_on_error:
                    self.logger.info("Stop on error is true and reached retries ({}). Bot is going to stop...".format(self.retries))
                    self.logger.error("BOT STOPPED! Error. Stop on error is true and reached retries ({}).\n\nNgen responses:\n{}\n\nComplete traceback:\n{}\n\nAddress: {} - Feed: {} - Type: {}\n\nJson:\n{}".format(self.retries, e, tb, address, incident_feed, incident_type, evidence))
                    self.stop()
                elif self.retries < 0 and counter < -50:
                    self.logger.error("Bot tried up to 50 times but cannot upload incident, it will keep retrying infinitely because retries is a negative value.\n\nNgen responses:\n{}\n\nComplete traceback:\n{}\n\nAddress: {} - Feed: {} - Type: {}\n\nJson:\n{}".format(e, tb, address, incident_feed, incident_type, evidence))
        
        self.acknowledge_message()


BOT = RestAPINgenOutputBot
