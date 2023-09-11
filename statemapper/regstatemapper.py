import re
from statemapper.statemapper import StateFormatter
from mappers import reg_templates
import xml.etree.ElementTree as ET

class WindowsRegistryFormatter(StateFormatter):
    """Formatter for windows registry states."""

    template_mapping = {
        "reg_templates.py": reg_templates.state_template_mapping_win_reg,
    }

    def get_artifact_type(self, complex_check):
        """Extract the artifact type from a complex check."""
        artifact_type = complex_check.find(".//ae:artifact", {"ae": "http://benchmarks.cisecurity.org/ae/0.5"}).attrib["type"]
        return artifact_type

    def extract_registry_data(self, artifact_element, test_element, ns):
    
        if "windows.user_registry_value_v1" in artifact_element.attrib["type"]:
            hive = "HKEY_USERS"
            # Extrahieren Sie registry_type aus dem ae:test-Element
            registry_data_type = test_element.find(".//ae:parameter[@name='registry_type']", ns).text
        else:
            hive = artifact_element.find(".//ae:parameter[@name='hive']", ns).text
            registry_data_type = artifact_element.find(".//ae:parameter[@name='registry_data_type']", ns).text
                
        key = artifact_element.find(".//ae:parameter[@name='key']", ns).text
        name = artifact_element.find(".//ae:parameter[@name='name']", ns).text
            
        return hive, key, name, registry_data_type


    def get_value(self, test_element):
        """Extract the value from a test element."""
        value_element = test_element.find(".//ae:parameter[@name='value']", {"ae": "http://benchmarks.cisecurity.org/ae/0.5"})
        return value_element.text if value_element is not None else None

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
        formatted_states = []
        try:
            for complex_check in complex_checks:
                formatted_id = self.get_formatted_id(rule, complex_check)
                artifact_element = complex_check.find(".//ae:artifact", ns)
                test_element = complex_check.find(".//ae:test", ns)
                test_type = test_element.attrib["type"]
                artifact_type = artifact_element.attrib["type"]

                hive, key, name, registry_data_type = self.extract_registry_data(artifact_element, test_element, ns)
                registry_path = f"{hive}\\{key}"

                if test_type == "existence_test":
                    value = test_element.find(".//ae:parameter[@name='value']", ns).text
                    if value == "none_exist":
                        template_type = "reg.absent"
                        sub_template_type = "existence_test"
                elif test_type == "windows.registry.value" or test_type == "windows.user_registry_value_v1":
                    template_type = "reg.present"
                    if registry_data_type == "reg_multi_sz":
                        sub_template_type = "multi_reg_sz"
                    elif artifact_type == "windows.user_registry_value_v1":
                        sub_template_type = "windows.user_registry"
                    else:
                        sub_template_type = "windows.registry.value"

                value = self.get_value(test_element)

                state_template = self.template_mapping["reg_templates.py"][template_type][sub_template_type]

                formatted_state = state_template.format(
                    sls="{{ sls }}",
                    ruleid=formatted_id,
                    registry_path=registry_path,
                    vname=name,
                    vtype=registry_data_type,
                    vdata=value
                )

                formatted_states.append(formatted_state) # Add the formatted state to the list
            return formatted_states
        except Exception as e:
            print(f"Error processing rule: {rule.id}")
            raise e
