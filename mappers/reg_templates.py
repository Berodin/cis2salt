# mappers/reg_templates.py

state_template_mapping_win_reg = {
    "reg.present": {
        
        "windows.registry.value":
          
 """{{{{ sls }}}}_{ruleid}:
  reg.present:
    - name: '{registry_path}'
    - vname: {vname}
    - vtype: {vtype}
    - vdata: '{vdata}'
    """,
    
        "multi_reg_sz":
          
 """{{{{ sls }}}}_{ruleid}:
  reg.present:
    - name: '{registry_path}'
    - vname: {vname}
    - vtype: {vtype}
    - vdata:
      {vdata}
      """,
      
        "windows.user_registry":
          
"""{{% for usersid in grains['hkey_users_sids'] %}}
{{{{ sls }}}}_{ruleid}_{{{{ usersid }}}}:
  reg.present:
    - name: '{registry_path}'
    - vname: {vname}
    - vtype: {vtype}
    - vdata: '{vdata}'
{{% endfor %}}
""",
    },
    
    "reg.absent": {
        "existence_test":
            
"""{{{{ sls }}}}_{ruleid}:
  reg.absent:
    - name: '{registry_path}'
    - vname: {vname}
    """,
    }
}
