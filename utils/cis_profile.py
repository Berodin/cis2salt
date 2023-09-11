# utils.cis_profile.py
class CISProfile:
    """Represents a profile in a CIS XCCDF Benchmark file."""

    def __init__(self, profile_elem, ns):
        """Initialize the profile with an XML element and a namespace."""
        self.id = profile_elem.attrib['id']
        self.title = profile_elem.find('xccdf:title', ns).text
        self.selected_rules = [select.attrib['idref'] for select in profile_elem.findall('xccdf:select', ns)]
