# utils.state_writer.py

import os

def write_states_to_file(states, filename):
    """Write a list of states to a file."""
    
    # Ensure 'output' directory exists, if not, create it
    if not os.path.exists('output'):
        os.makedirs('output')
    
    # Modify the filename to save it inside 'output' directory
    output_path = os.path.join('output', f"{filename}.txt")
    
    with open(output_path, 'w') as f:
        for state in states:
            f.write(state)
            f.write("\n")
