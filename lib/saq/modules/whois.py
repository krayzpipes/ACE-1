"""Module for whois analysis of domain names.

A few outcomes can be expected and must be handled.

**Note that although some of these results do not tell an analyst the
'creation time' of the domain, the lack of creation time might
say 'something' to the analyst about that domain/zone:

    1. The TLD is unknown/unsupported by the whois package.
    2. The result is an object of Nonetype -- no result found.
    3. The whois result for the TLD doesn't include
        a creation time.
    4. Whois linux program is not installed in the OS of the
        analysis server.
    5. There were actual results.
"""

import logging
from datetime import datetime

import whois
from whois.exceptions import UnknownTld

from saq.analysis import Analysis, Observable
from saq.constants import *
from saq.modules import AnalysisModule

KEY_DATETIME_CREATED = "datetime_created"
KEY_DATETIME_OF_ANALYSIS = "datetime_of_analysis"
KEY_AGE_IN_DAYS = "age_in_days"
KEY_ZONE_NAME = "zone_name"

class WhoisAnalysis(Analysis):
    """How long ago was the domain registered?"""

    def initialize_details(self):
        self.details = {
            KEY_ZONE_NAME: None,
            KEY_AGE_IN_DAYS: None,
            KEY_DATETIME_CREATED: None,
            KEY_DATETIME_OF_ANALYSIS: None,
        }
        self.tld_not_supported = False
        self.create_datetime_not_found = False
        self.no_result = False
        self.whois_not_installed = False


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

        _message = "Whois Analysis - {}"
        message = None

        if self.tld_not_supported:
            message = _message.format("TLD not supported.")

        if self.no_result:
            message = _message.format("FQDN doesn't exist.")

        if self.create_datetime_not_found:
            message = _message.format("Result does not include creation datetime.")

        if self.whois_not_installed:
            message = _message.format(
                "Whois linux program not installed on analysis server"
            )

        if message is None:
            # Include the zone name because you can send an entire
            # FQDN to the whois program, and the root zone is actually
            # what is looked up. This is that there is no confusion
            # for the analyst in whether whois attempted to lookup a
            # FQDN/subdomain or the root zone.

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

    def execute_analysis(self, _fqdn):
        """Executes analysis for Whois analysis of domains/zones."""

        try:
            logging.debug("Beginning whois analysis of {}".format(_fqdn))
            result = whois.query(_fqdn)

        # whois python module doesn't know about the TLD of the FQDN
        except UnknownTld:
            # TODO Update analysis - Set tld not supported.
            logging.debug("TLD not supported for {}.".format(_fqdn))
            return True  # Still tells an analyst something about the domain.

        except FileNotFoundError:
            # TODO Update analysis - whois not installed
            logging.debug("Whois not installed on analysis server.")
            return True

        else:
            # If TLD was valid but domain wasn't found.
            if result is None:
                # TODO Update analysis - No result received
                logging.debug(
                    "No result received from whois analysis of {}".format(_fqdn)
                )
                return True # return analysis

            # If creation date not reported back from whois server.
            if "creation_date" not in result.__dict__.keys():
                # TODO Update analysis - Result does not include creation datetime
                logging.debug(
                    "Result does not include creation datetime for {}".format(_fqdn)
                )
                return True

            if






