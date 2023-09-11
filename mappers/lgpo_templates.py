# mappers/lgpo_templates.py

state_template_mapping_lgpo = {
    "equals":"""
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: {policy_class}
    - setting: 
      - '{value}'""",
    
    
    
    
    "existence_test":"""
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: {policy_class}
    - setting: 
      - '{value}'""",
                
                
            
                
    "list":"""
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: {policy_class}
    - setting:
      {values}""",
      
      
      
            
    "pattern match":"""
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: {policy_class}
    - setting:
      {values}""",
        
 
 
 
     "set.white_list_v1":"""
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: {policy_class}
    - setting:
      {values}""",
               
      
      
           "windows.user_sid55":"""
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: {policy_class}
    - setting: {value}""",
      
        
        
        
    "greater than or equal":"""
{{% set min_{policy_name_underlined} = {value} %}}
{{% set current_{policy_name_underlined} = salt['lgpo.get_policy']('{policy_name}','{policy_class}')|int %}}
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: '{policy_class}'
    - setting: {{{{ min_{policy_name_underlined} }}}}
    - onlyif:
    - fun: bits_utils.get_truth
        args:
        - {{{{ current_{policy_name_underlined} }}}}
        - lt
        - {{{{ min_{policy_name_underlined} }}}}
        """,
    
    
    
        "greater than":"""
{{% set min_{policy_name_underlined} = {value} %}}
{{% set current_{policy_name_underlined} = salt['lgpo.get_policy']('{policy_name}','{policy_class}')|int %}}
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: '{policy_class}'
    - setting: {{{{ min_{policy_name_underlined} }}}}
    - onlyif:
    - fun: bits_utils.get_truth
        args:
        - {{{{ current_{policy_name_underlined} }}}}
        - le
        - {{{{ min_{policy_name_underlined} }}}}
        """,
        
    
    
    "less than or equal":"""
{{% set max_{policy_name_underlined} = {value} %}}
{{% set current_{policy_name_underlined} = salt['lgpo.get_policy']('{policy_name}','{policy_class}')|int %}}
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: '{policy_class}'
    - setting: {{{{ max_{policy_name_underlined} }}}}
    - onlyif:
    - fun: bits_utils.get_truth
        args:
        - {{{{ current_{policy_name_underlined} }}}}
        - ge
        - {{{{ max_{policy_name_underlined} }}}}
        """,
        
            "windows.sid_sid_trustee_name_v1":"""
{{{{ sls }}}}_{ruleid}:
  lgpo.set:
    - name: '{policy_name}'
    - policy_class: {policy_class}
    - setting: '{value}'""",
    
}
