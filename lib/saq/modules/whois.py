"""Module for whois analysis of domain names."""

import logging
from datetime import datetime

import whois
from whois.exceptions import UnknownTld

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.modules import AnalysisModule

KEY_DATETIME_CREATED = "datetime_created"
KEY_AGE_IN_DAYS = "age_in_days"
KEY_ZONE_NAME = "zone_name"

class WhoisAnalysis(Analysis):
    """How long ago was the domain registered?"""

    def initialize_details(self):
        self.details = {
            KEY_ZONE_NAME: None,
            KEY_AGE_IN_DAYS: None,
            KEY_DATETIME_CREATED: None,
        }
        self.tld_not_supported = False
        self.create_datetime_not_found = False
        self.no_result = False
        self.who_is_not_found = False


    @property
    def jinja_template_path(self):
        # Need to implement
        pass

    @property
    def create_datetime(self):
        return self.details[KEY_DATETIME_CREATED]

    @create_datetime.setter
    def create_datetime(self, value):
        self.details[KEY_DATETIME_CREATED] = value

    @property
    def age_in_days(self):
        return self.details[KEY_AGE_IN_DAYS]

    @age_in_days.setter
    def age_in_days(self, value):
        self.details[KEY_AGE_IN_DAYS] = value

    @property
    def zone_name(self):
        return self.details[KEY_ZONE_NAME]

    @zone_name.setter
    def zone_name(self, value):
        self.details[KEY_ZONE_NAME] = value

    def generate_summary(self):
        """Return analysis result string for alert analysis page."""

        _message = "WhoIS Analysis - {}"
        message = None

        if self.tld_not_supported:
            message = _message.format("TLD not supported.")

        if self.no_result:
            message = _message.format("Domain doesn't exist.")

        if self.create_datetime_not_found:
            message = _message.format("Result does not include creation datetime.")

        if self.who_is_not_found:
            message = _message.format(
                "Analysis server does not have Whois program installed."
            )

        if message is None:
            _status = "{} is {} days old.".format(
                self.details[KEY_ZONE_NAME],
                self.details[KEY_AGE_IN_DAYS],
            )
            message = _message.format(_status)

        return message


class WhoisAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WhoisAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    def execute_analysis(self, fqdn):
        try:
            logging.debug("Beginning whois analysis of {}".format(fqdn))
            result = whois.query(fqdn)
        except UnknownTld:
            # TODO Update analysis - Set tld not supported.
            logging.debug("TLD not supported for {}.".format(fqdn))
            return True # return analysis
        else:
            # If TLD was valid but domain wasn't found.
            if result is None:
                # TODO Update analysis - No result received
                logging.debug(
                    "No result received from whois analysis of {}".format(fqdn)
                )
                return True # return analysis

            if "creation_date" not in result.__dict__.keys():
                # TODO Update analysis - Result does not include creation datetime
                logging.debug(
                    "Result does not include creation datetime for {}".format(fqdn)
                )
                return True







