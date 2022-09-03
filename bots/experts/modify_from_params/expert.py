# -*- coding: utf-8 -*-
"""
Modify Expert bot let's you manipulate all fields with parameters "if_" and "then_"
"""
import re
import sys

from intelmq.lib.bot import Bot


def is_re_pattern(value):
    """
    Checks if the given value is a re compiled pattern
    """
    if sys.version_info > (3, 7):
        return isinstance(value, re.Pattern)
    else:
        return hasattr(value, "pattern")


class MatchGroupMapping:

    """Wrapper for a regexp match object with a dict-like interface.
    With this, we can access the match groups from within a format
    replacement field.
    """

    def __init__(self, match):
        self.match = match

    def __getitem__(self, key):
        return self.match.group(key)

# TODO: Change Bot to ExpertBot on version 3.0.2
class ModifyIfThenConfigExpertBot(Bot):
    """Modify From Params bot can make nearly arbitrary changes to 
    event's fields based on regex-rules on different values defined 
    in bots params. See docs/Bots.md for some examples."""
    case_sensitive: bool = True
    overwrite: bool = True

    def init(self):
        if_params = {k: v for k, v in self.__dict__.items() if k.startswith('if_')}

        if self.case_sensitive:
            self.re_kwargs = {}
        else:
            self.re_kwargs = {'flags': re.IGNORECASE}

        # regex compilation
        self.config = []
        for p_if_name, p_if in if_params.items():
            if type(p_if) is dict:
                self.logger.info(
                    "Parameter if {} is dict {}.".format(p_if_name, p_if))
            else:
                self.logger.error(
                    "Parameter {} isn't list or str, I can't process it.".format(p_if_name))

            rulename = '_'.join(p_if_name.split('_')[1:])
            p_then_name = 'then_' + rulename
            p_then = getattr(self, p_then_name)
            if type(p_then) is dict:
                self.logger.info(f"Parameter if {p_then_name} is dict {p_then}.")
            else:
                self.logger.error(f"Parameter {p_then_name} isn't list or str, I can't process it.")

            self.config.append({
                'rulename': rulename,
                'if': p_if,
                'then': p_then
            })

            for rule in self.config:
                for field, expression in rule["if"].items():
                    if isinstance(expression, str) and expression != '':
                        self.config[-1]["if"][field] = re.compile(
                            expression, **self.re_kwargs)

    def matches(self, identifier, event, condition):
        matches = {}

        for name, rule in condition.items():
            # empty string means non-existent field
            if rule == '':
                if name in event:
                    return None
                else:
                    continue
            if name not in event:
                return None
            if is_re_pattern(rule):
                if isinstance(event[name], (int, float)):
                    match = rule.search(str(event[name]))
                    if match is None:
                        return None
                    else:
                        matches[name] = match
                else:
                    match = rule.search(event[name])
                    if match is None:
                        return None
                    else:
                        matches[name] = match
            else:  # rule is boolean, int, float, etc
                if event[name] != rule:
                    return None

        return matches

    def apply_action(self, event, action, matches):
        for name, value in action.items():
            try:
                newvalue = value.format(msg=event,
                                        matches={k: MatchGroupMapping(v)
                                                 for (k, v) in matches.items()})
            except AttributeError:  # value has ne format: int, bool etc
                newvalue = value
            event.add(name, newvalue,
                      overwrite=self.overwrite)

    def process(self):
        event = self.receive_message()

        for rule in self.config:
            rule_id, rule_selection, rule_action = rule['rulename'], rule['if'], rule['then']
            matches = self.matches(rule_id, event, rule_selection)
            if matches is not None:
                self.logger.debug('Apply rule %s.', rule_id)
                self.apply_action(event, rule_action, matches)

        self.send_message(event)
        self.acknowledge_message()


BOT = ModifyIfThenConfigExpertBot
