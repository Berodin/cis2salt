# utils.xml_parser.py
from .cis_profile import CISProfile
from .group import Group
from .rule import Rule
import xml.etree.ElementTree as ET

class XMLParser:
    """XML Parser for CIS XCCDF Benchmark files."""

    ns = {
        'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
        'xhtml': 'http://www.w3.org/1999/xhtml',
        'ae': 'http://benchmarks.cisecurity.org/ae/0.5',
        'ns0': 'http://checklists.nist.gov/xccdf/1.2',
        'ns1': 'http://benchmarks.cisecurity.org/ae/0.5'
    }

    def __init__(self, xml_file):
        """Initialize the parser with the path to an XML file."""
        self.tree = ET.parse(xml_file)
        self.root = self.tree.getroot()

    def get_profiles(self):
        """Extract and return profiles from the XML file."""
        profiles = {}
        for profile_elem in self.root.findall('xccdf:Profile', self.ns):
            profile = CISProfile(profile_elem, self.ns)
            profiles[profile.id] = profile
        return profiles

    def get_groups(self):
        """Extract and return groups from the XML file."""
        groups = {}
        for group_elem in self.root.findall('xccdf:Group', self.ns):
            group = Group(group_elem, self.ns)
            groups[group.id] = group
        return groups

    def get_group_title(self, group_id):
        groups = self.get_groups()
        group = groups.get(group_id)
        if group is not None:
            return group.title
        return None

    def get_rules(self):
        """Extract and return all rules from the XML file."""
        rules = {}
        for rule_elem in self.root.findall('.//xccdf:Rule', self.ns):  # Search all subelements
            rule = Rule(rule_elem, self.ns)
            rules[rule.id] = rule
        return rules
