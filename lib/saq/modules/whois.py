"""Module for whois analysis of domain names.

A few outcomes can be expected and must be handled.

**Note that although some of these results do not tell an analyst the
'creation time' of the domain, the lack of creation time might
say 'something' to the analyst about that domain/zone. Some things to
consider:

    - The TLD is unknown/unsupported by the whois package.
    - The result is an object of Nonetype -- no result found.
    - The whois result for the TLD doesn't include
        a creation time.
    - Whois linux program is not installed in the OS of the
        analysis server.
    - There were actual results.
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
        self.creation_datetime_not_found = False
        self.no_result = False
        self.whois_not_installed = False
        self.creation_datetime_wrong_format = False


    @property
    def jinja_template_path(self):
        return "analysis/whois.html"

    @property
    def creation_datetime(self):
        return self.details[KEY_DATETIME_CREATED]

    @creation_datetime.setter
    def creation_datetime(self, value):
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

        if self.creation_datetime_not_found:
            message = _message.format("Result does not include creation datetime.")

        if self.creation_datetime_wrong_format:
            message = _message.format("Creation datetime in wrong format.")

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

            _status = f"{self.details[KEY_ZONE_NAME]} is " \
                      f"{self.details[KEY_AGE_IN_DAYS]} days old."
            message = _message.format(_status)

        return message


class WhoisAnalyzer(AnalysisModule):  # deep

    @property
    def generated_analysis_type(self):
        return WhoisAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    def execute_analysis(self, _fqdn):
        """Executes analysis for Whois analysis of domains/zones."""

        analysis = self.create_analysis(_fqdn)
        analysis.logs = self.json()

        fqdn = _fqdn.value

        try:
            logging.debug(f"Beginning whois analysis of {fqdn}")
            result = whois.query(fqdn)

        # whois python module doesn't know about the TLD of the FQDN
        except UnknownTld:
            analysis.tld_not_supported = True
            logging.debug(f"TLD not supported by for {fqdn}.")
            return True  # Still tells an analyst something about the domain.

        except FileNotFoundError:
            analysis.whois_not_installed = True
            logging.debug("Whois program not installed on analysis server.")
            return True

        else:
            if result is None:
                analysis.no_result = True
                logging.debug(f"No result received from whois analysis of {fqdn}")
                return True

            if 'name' not in result.__dict__.keys():
                analysis.zone_name = "NO_NAME_RETURNED"
                logging.debug(f"Result did not include name attribute for {fqdn}")
            else:
                analysis.zone_name = result.name

            # If creation date not reported back from whois server.
            # This happens on certain TLDs
            if "creation_date" not in result.__dict__.keys():
                analysis.creation_datetime_not_found = True
                logging.debug(f"Result does not include creation datetime for {fqdn}")
                return True

            # If creation date is not a datetime object as expected
            if not isinstance(result.creation_date, datetime):
                analysis.creation_datetime_wrong_format = True
                logging.debug(f"Creation datetime in unexpected format for {fqdn}")
                return True

            _now = datetime.now()
            _delta = _now - result.creation_date
            
            analysis.creation_datetime = result.creation_date.isoformat(' ')
            analysis.analysis_datetime = _now.isoformat(' ')

            # Days will appear as a negative anytime 'now' is less than
            # the whois creation time.. added in case of timezone
            # issues.
            if _delta.days < 0:
                analysis.age_in_days = "0"
                return True

            # Floor value, because I'm paranoid.
            age_in_days = _delta.seconds // 86400

            analysis.age_in_days = str(age_in_days)

            return True
