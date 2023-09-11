# utils.group.py
from .rule import Rule

class Group:
    """Represents a group in a CIS XCCDF Benchmark file."""

    def __init__(self, group_elem, ns):
        """Initialize the group with an XML element and a namespace."""
        self.id = group_elem.attrib['id']
        self.title = group_elem.find('xccdf:title', ns).text
        self.rules = self._extract_rules_from_group(group_elem, ns)

    def _extract_rules_from_group(self, group, ns):
        """Recursively extract rules from a group (including its subgroups)."""
        rules = [Rule(rule, ns) for rule in group.findall('xccdf:Rule', ns)]
        for subgroup in group.findall('xccdf:Group', ns):
            rules.extend(self._extract_rules_from_group(subgroup, ns))
        return rules
