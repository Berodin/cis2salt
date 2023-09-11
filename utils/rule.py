# utils.rule.py
import xml.etree.ElementTree as ET

class Rule:
    """Represents a rule in a CIS XCCDF Benchmark file."""

    def __init__(self, rule_elem, ns):
        """Initialize the rule with an XML element and a namespace."""
        self.id = rule_elem.attrib['id']
        self.title = rule_elem.find('xccdf:title', ns).text.strip()
        self.description = self._get_html_content(rule_elem.find('xccdf:description', ns))
        self.rationale = self._get_html_content(rule_elem.find('xccdf:rationale', ns))
        self.fixtext = self._get_html_content(rule_elem.find('xccdf:fixtext', ns)) if rule_elem.find('xccdf:fixtext', ns) is not None else None
        self.idents = [ident.text for ident in rule_elem.findall('xccdf:ident', ns)]
        self.complex_check = rule_elem.find('xccdf:complex-check', ns)  # Keep the element object

    def _get_html_content(self, elem):
        """Return the HTML content of an element as a string."""
        return ''.join(ET.tostring(e, encoding='unicode') for e in elem)
