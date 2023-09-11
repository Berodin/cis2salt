# statemapper/statemapper.py
class StateFormatter:
    """Base class for state formatters."""

    def format_state(self, rule, artifact, test, params):
        """Format a state based on a rule, an artifact, a test, and parameters."""
        raise NotImplementedError("Subclasses must implement this method.")

state_formatters = {}

def format_state(state_type, rule, artifact, test, params):
    """Format a state based on its type, a rule, an artifact, a test, and parameters."""
    if state_type not in state_formatters:
        if state_type == "lgpo.set":
            from statemapper.lgpostatemapper import LgpoSetFormatter
            state_formatters[state_type] = LgpoSetFormatter()
        else:
            raise ValueError(f"Unknown state type: {state_type}")
    return state_formatters[state_type].format_state(rule, artifact, test, params)
