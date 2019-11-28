"""Module for whois analysis of domain names.

A few outcomes can be expected and must be handled.

**Note that although some of these whois_results do not tell an analyst the
'creation time' of the domain, the lack of creation time might
say 'something' to the analyst about that domain/zone. Some things to
consider:

    - The TLD is unknown/unsupported by the whois package.
    - The whois_result is an object of Nonetype -- no whois_result found.
    - The whois whois_result for the TLD doesn't include
        a creation time.
    - Whois linux program is not installed in the OS of the
        analysis server.
    - There were actual whois_results.
"""

import logging
from datetime import datetime

from saq.analysis import Analysis, Observable
from saq.constants import F_FQDN
from saq.modules import AnalysisModule


KEY_AGE_CREATED_IN_DAYS = "age_created_in_days"
KEY_AGE_LAST_UPDATED_IN_DAYS = "age_last_updated_in_days"
KEY_DATETIME_CREATED = "datetime_created"
KEY_DATETIME_OF_ANALYSIS = "datetime_of_analysis"
KEY_DATETIME_OF_LAST_UPDATE = "datetime_of_last_update"
KEY_NAME_SERVERS = "nameservers"
KEY_REGISTRAR = "registrar"
KEY_ZONE_NAME = "zone_name"


class WhoisAnalysis(Analysis):
    """How long ago was the domain registered?"""

    def initialize_details(self):
        self.details = {
            KEY_AGE_CREATED_IN_DAYS: None,
            KEY_AGE_LAST_UPDATED_IN_DAYS: None,
            KEY_DATETIME_CREATED: None,
            KEY_DATETIME_OF_ANALYSIS: None,
            KEY_DATETIME_OF_LAST_UPDATE: None,
            KEY_NAME_SERVERS: None,
            KEY_REGISTRAR: None,
            KEY_ZONE_NAME: None,
        }

        self.datetime_created_missing_or_invalid = False
        self.datetime_updated_missing_or_invalid = False
        self.datetime_unknown_date_format = False
        self.domain_not_found = False
        self.tld_not_supported = False
        self.whois_linux_not_installed = False
        self.whois_python_package_not_installed = False
        self.datetime_created_unsupported_format = False

    @property
    def jinja_template_path(self):
        return "analysis/whois.html"

    # How many days ago the domain was registered.
    @property
    def age_created_in_days(self):
        return self.details[KEY_AGE_CREATED_IN_DAYS]

    @age_created_in_days.setter
    def age_created_in_days(self, value):
        self.details[KEY_AGE_CREATED_IN_DAYS] = value

    # How many days ago the domain was updated.
    @property
    def age_last_updated_in_days(self):
        return self.details[KEY_AGE_LAST_UPDATED_IN_DAYS]

    @age_last_updated_in_days.setter
    def age_last_updated_in_days(self, value):
        self.details[KEY_AGE_LAST_UPDATED_IN_DAYS] = value

    # The date/time the domain was registered.
    @property
    def datetime_created(self):
        return self.details[KEY_DATETIME_CREATED]

    @datetime_created.setter
    def datetime_created(self, value):
        self.details[KEY_DATETIME_CREATED] = value

    # The date/time the analysis was performed.
    @property
    def datetime_of_analysis(self):
        return self.details[KEY_DATETIME_OF_ANALYSIS]

    @datetime_of_analysis.setter
    def datetime_of_analysis(self, value):
        self.details[KEY_DATETIME_OF_ANALYSIS] = value

    # The date/time the domain was last updated.
    @property
    def datetime_of_last_update(self):
        return self.details[KEY_DATETIME_OF_LAST_UPDATE]

    @datetime_of_last_update.setter
    def datetime_of_last_update(self, value):
        self.details[KEY_DATETIME_OF_LAST_UPDATE] = value

    # The name servers associated with the domain
    @property
    def nameservers(self):
        return self.details[KEY_NAME_SERVERS]

    @nameservers.setter
    def nameservers(self, value):
        self.details[KEY_NAME_SERVERS] = value

    # The registrar for the domain.
    @property
    def registrar(self):
        return self.details[KEY_REGISTRAR]

    @registrar.setter
    def registrar(self, value):
        self.details[KEY_REGISTRAR] = value

    # The root zone name.
    @property
    def zone_name(self):
        return self.details[KEY_ZONE_NAME]

    @zone_name.setter
    def zone_name(self, value):
        self.details[KEY_ZONE_NAME] = value

    def generate_summary(self):
        """Return analysis whois_result string for alert analysis page."""

        _prepend = "Whois Analysis"
        _created = "CREATED"
        _updated = "LAST UPDATED"
        message = None
        created = None
        updated = None

        # Conditions affecting both Created and Last Updated:
        if self.tld_not_supported:
            message = f"{_prepend} - TLD not supported by python whois module."

        if self.domain_not_found:
            message = f"{_prepend} - domain not found."
        
        if self.datetime_unknown_date_format:
            message = f"{_prepend} - unknown date format returned."

        if self.whois_linux_not_installed:
            message = f"{_prepend} - whois program for linux not " \
                      f"installed."
        
        if self.whois_python_package_not_installed:
            message = f"{_prepend} - whois python module not installed."

        # Conditions affecting one or both created/last updated datetimes.
        if self.datetime_created_missing_or_invalid:
            created = f"{_created}: missing or invalid whois response."

        if self.datetime_updated_missing_or_invalid:
            updated = f"{_updated}: missing or invalid whois response."

        # If no major issues, create the final message
        if message is None:

            if created is None:
                created = f"{_created}: {self.age_created_in_days} days old."

            if updated is None:
                updated = f"{_updated}: {self.age_last_updated_in_days} days old."

            message = f"{_prepend} - {self.zone_name} - {created} {updated}"

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

        analysis = self.create_analysis(_fqdn)
        # analysis.logs = self.json()

        fqdn = _fqdn.value

        logging.debug(f"Beginning whois analysis of {fqdn}")

        # Check to see if the whois python module is installed or not.
        try:
            import whois
            from whois.exceptions import (
                FailedParsingWhoisOutput,
                UnknownDateFormat,
                UnknownTld,
                WhoisCommandFailed,
            )
        except ModuleNotFoundError:
            analysis.whois_python_package_not_installed = True
            logging.debug("Whois python module is not installed.")
            return True

        # Make the whois query.
        try:
            whois_result = whois.query(fqdn)
        
        except (FailedParsingWhoisOutput, WhoisCommandFailed):
            analysis.command_failed = True
            logging.debug(f"Whois command general failure or failure parsing output.")
            return True

        # Whois python module doesn't know about the TLD of the FQDN.
        except UnknownTld:
            analysis.tld_not_supported = True
            logging.debug(f"TLD not supported by whois python module.")
            return True

        # Whois is not installed on the analysis server.
        except FileNotFoundError:
            analysis.whois_linux_not_installed = True
            logging.debug("Whois program not installed on analysis server.")
            return True

        # Whois python module received a date in a format it wasn't
        # expecting.
        except UnknownDateFormat:
            analysis.datetime_unknown_date_format = True
            logging.debug("Unknown date format in whois response.")
            return True

        else:
            if whois_result is None:
                analysis.domain_not_found = True
                logging.debug(f"No whois_result / domain not found.")
                return True

            # Check for zone name returned from whois query.
            if ('name' not in whois_result.__dict__.keys()) or (not whois_result.name):
                analysis.zone_name = "NO_ZONE_NAME_RETURNED"
                logging.debug(f"Result did not include valid zone name.")
            else:
                analysis.zone_name = whois_result.name

            # creation date validation
            if ("creation_date" not in whois_result.__dict__.keys()) or (not isinstance(whois_result.creation_date, datetime)):
                analysis.datetime_created_missing_or_invalid= True
                logging.debug(f"Result does not include creation datetime.")

            # last updated date validation
            if ("last_updated" not in whois_result.__dict__.keys()) or (not isinstance(whois_result.last_updated, datetime)):
                analysis.datetime_updated_missing_or_invalid = True
                logging.debug(f"Result does not include last updated datetime.")

            _now = datetime.now()

            analysis.analysis_datetime = _now.isoformat(' ')

            def age_in_days_as_string(past, present):
                _delta = present - past
                # Days are negative if past is actually after the
                # present. Probably an indication of time zone issues so
                # assume it's less than a day.
                if _delta.days < 0:
                    return "0"
                return str(_delta.days)

            if not analysis.datetime_created_missing_or_invalid:
                analysis.datetime_created = whois_result.creation_date.isoformat(' ')
                analysis.age_created_in_days = age_in_days_as_string(whois_result.creation_date, _now)

            if not analysis.datetime_updated_missing_or_invalid:
                analysis.datetime_of_last_update= whois_result.last_updated.isoformat(' ')
                analysis.age_last_updated_in_days = age_in_days_as_string(whois_result.last_updated, _now)

            return True
