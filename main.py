# main.py
import argparse
from statemapper.lgpostatemapper import LgpoSetFormatter
from statemapper.regstatemapper import WindowsRegistryFormatter
from utils.state_writer import write_states_to_file
from utils.xml_parser import XMLParser
import os



def profile_name_to_id(name):
    if name.lower() == 'lvl1':
        return 'xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Member_Server'
    elif name.lower() == 'lvl2':
        return 'xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Member_Server'
    else:
        raise ValueError(f"Unknown profile name: {name}")

def get_rules_from_profiles(parser, *profile_names):
    profiles = parser.get_profiles()
    groups = parser.get_groups()

    selected_rule_ids = set()
    for name in profile_names:
        profile_id = profile_name_to_id(name)
        selected_rule_ids.update(profiles[profile_id].selected_rules)

    group_rules = {}
    for group in groups.values():
        for rule in group.rules:
            if rule.id in selected_rule_ids:
                if group.id not in group_rules:
                    group_rules[group.id] = []
                group_rules[group.id].append(rule)

    return group_rules

# utils.artifact_mapping.py
artifact_mapping = {
    "windows.registry.value": {"formatter": WindowsRegistryFormatter, "template": "reg_templates.py"},
    "windows.user_registry_value_v1": {"formatter": WindowsRegistryFormatter, "template": "reg_templates.py"},
    "windows.passwordpolicyobject": {"formatter": LgpoSetFormatter, "template": "lgpo_templates.py"},
    "windows.userrightsassignment": {"formatter": LgpoSetFormatter, "template": "lgpo_templates.py"},
    "windows.lockoutpolicyobject": {"formatter": LgpoSetFormatter, "template": "lgpo_templates.py"},
    "windows.userrightsassignmentdeny": {"formatter": LgpoSetFormatter, "template": "lgpo_templates.py"},
    "windows.user_sid55": {"formatter": LgpoSetFormatter, "template": "lgpo_templates.py"},
    "windows.sid_sid_v1": {"formatter": LgpoSetFormatter, "template": "lgpo_templates.py"},
    "windows.rsop.security_setting_boolean": {"formatter": LgpoSetFormatter, "template": "lgpo_templates.py"},
    "windows.auditeventsubcategories": {"formatter": LgpoSetFormatter, "template": "lgpo_templates.py"},
    # Add other mappings as needed
}

def process_group_rules(group_rules, parser):
    for group_id, rules in group_rules.items():
        group_states = []
        for rule in rules:
            complex_check_list = rule.complex_check
            ns = parser.ns
            if not complex_check_list:
                # no complex check is given. This means that no automatic remediation advice is given by CIS
                print(f"Warning: complex_check_list is empty for rule {rule.id}")
                continue
            
            # Check whether an artefact is found in the complex check. If not, not enough details for automatic remediation are given by CIS
            artifact_element = complex_check_list[0].find(".//ae:artifact", ns)
            if artifact_element is None:
                print(f"Warning: No artifact element found for rule {rule.id}")
                continue
            
            # get artifact type
            artifact_type = complex_check_list[0].find(".//ae:artifact", ns).attrib["type"]

            # Get corresponding formatter for the detected artifact type
            formatter_class = artifact_mapping.get(artifact_type, {"formatter": LgpoSetFormatter})["formatter"]
            formatter = formatter_class()  

            group_states += formatter.format_states(rule, complex_check_list, artifact_mapping, ns)

        # Get the title of the group
        group_title = parser.get_group_title(group_id)
        # Write the states to a file named after the group title
        write_states_to_file(group_states, group_title)

if __name__ == '__main__':
    # Create Argument Parser
    parser = argparse.ArgumentParser(description='Process XML file and extract rules for given profiles.')
    parser.add_argument('xml_file', type=str, help='Path to the XML file located inside the "inputfile" directory relative to the script location.')
    parser.add_argument('profiles', type=str, help='Comma-separated list of profiles, e.g., lvl1,lvl2')
    
    args = parser.parse_args()
    
    # Extract file path and profiles
    current_directory = os.path.dirname(os.path.abspath(__file__))
    xml_file_path = os.path.join(current_directory, "inputfile", args.xml_file)
    profile_names = args.profiles.split(',')
    
    # Initialize the XML Parser
    xml_parser = XMLParser(xml_file_path)
    
    # Extract and process rules from the given profiles
    group_rules = get_rules_from_profiles(xml_parser, *profile_names)
    process_group_rules(group_rules, xml_parser)