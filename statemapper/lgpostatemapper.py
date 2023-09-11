# statemapper/lgpostatemapper.py
from xml.etree.ElementTree import fromstring, ElementTree, tostring
from statemapper.statemapper import StateFormatter
from mappers import lgpo_templates
import re

class LgpoSetFormatter(StateFormatter):
    """Formatter for lgpo.set states."""

    template_mapping = {
        "lgpo_templates.py": lgpo_templates.state_template_mapping_lgpo,
        # Weitere Template-Dateien...
    }

    def get_artifact_type(self, complex_check):
        """Extract the artifact type from a complex check."""
        artifact_type = complex_check.find(".//ae:artifact", {"ae": "http://benchmarks.cisecurity.org/ae/0.5"}).attrib["type"]
        return artifact_type


    def get_policy_class_and_name(self, fixtext):
        """Extract policy class and name from a fixtext."""
        policy_class = "Machine"  # This is always the same

        # Parse the fixtext as XML and extract the text content of the html:code element
        tree = ElementTree(fromstring(fixtext))
        code_element = tree.find(".//html:code", {"html": "http://www.w3.org/1999/xhtml"})
        policy_name = code_element.text.split("\\")[-1].strip() if code_element is not None else None

        return policy_class, policy_name

    def parse_sids(self, value):
        """Parse a string of SIDs into a list of SIDs."""
        # Match a string like 'S-1-5-(32-544|11|9)'
        match = re.match(r"(.*?)-\(([\d|-]+)\)", value)
        if match:
            prefix, suffixes = match.groups()
            # Split the suffixes by '|', prepend the prefix to each one, and return the list
            return [prefix + "-" + suffix for suffix in suffixes.split("|")]
        else:
            return []

    def get_value_and_test_type(self, complex_check, ns, rule):
        """Extract value and test type from a complex check."""
        # complex_check is already an XML element, so we don't need to use fromstring
        tree = ElementTree(complex_check)
        test_type = tree.find(".//ae:test", ns).attrib["type"]
        try:
            value_element = tree.find(".//ae:parameter[@name='value']", ns)
            values_element = tree.find(".//ae:parameter[@name='values']", ns)

            if value_element is not None:
                value = value_element.text
                if value == "none_exist" and test_type == "existence_test":
                    value = "NONE"
            elif values_element is not None:
                value = values_element.text.split(",")
            else:
                value = None
            
            # If the test type is 'pattern match', parse the value as SIDs
            if test_type == "pattern match" and value is not None:
                value = self.parse_sids(value)
            
            return value, test_type

        except Exception as e:
            print(f"Error processing rule: {rule.id}")
            raise e

    def get_formatted_id(self, rule, complex_check):
        """Return the shortened ID for the rule."""
        match = re.search(r"rule_([\d.]+)_L[12]", rule.id)
        artifact_oval_id = complex_check.find(".//ae:artifact_oval_id", {"ae": "http://benchmarks.cisecurity.org/ae/0.5"}).text
        if match:
            rule_number = match.group(1)
            return f"rule_{rule_number}_{artifact_oval_id}"
        else:
            return rule.id

    def format_states(self, rule, complex_checks, artifact_mapping, ns):
        """Format states based on a rule, a list of complex checks, and a namespace."""
        formatted_states = []
        try:
            for complex_check in complex_checks:
                formatted_id = self.get_formatted_id(rule, complex_check)
                artifact_type = self.get_artifact_type(complex_check)
                policy_class, policy_name = self.get_policy_class_and_name(rule.fixtext) # Assuming fixtext is part of the rule
                policy_name_underlined = policy_name.replace(' ', '_')
                value, test_type = self.get_value_and_test_type(complex_check, ns, rule)

                # Select the template based on the artifact type for special cases
                if artifact_type == "windows.user_sid55" or artifact_type == "set.white_list_v1":
                    template_key = artifact_type
                else:
                    template_key = test_type

                template_file = artifact_mapping[artifact_type]["template"]
                state_template_mapping = self.template_mapping[template_file]  # Corrected variable name
                    
                state_template = state_template_mapping[template_key]

                # If the test type is 'pattern match' or 'set.white_list_v1', format the 'values' placeholder
                if isinstance(value, list):
                    value = "\n      ".join([f"- '{v}'" for v in value])
                    formatted_state = state_template.format(sls="{{ sls }}", ruleid=formatted_id, policy_name=policy_name, policy_name_underlined=policy_name_underlined, policy_class=policy_class, values=value)
                else:
                    formatted_state = state_template.format(sls="{{ sls }}", ruleid=formatted_id, policy_name=policy_name, policy_name_underlined=policy_name_underlined, policy_class=policy_class, value=value)

                formatted_states.append(formatted_state) # Add the formatted state to the list
            return formatted_states
        except Exception as e:
            print(f"Error processing rule: {rule.id}")
            raise e
