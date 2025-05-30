"""
Helper functions for port range handling

This module contains utility functions for working with port specifications.
"""

def port_in_range(port, port_spec):
    """
    Check if a port is included in a port specification
    
    Args:
        port: Port number (as string or int)
        port_spec: Port specification (e.g. "80", "1-1000")
        
    Returns:
        True if port is in the specification, False otherwise
    """
    port = int(port)
    
    if "-" in port_spec:
        # Range specification
        start, end = port_spec.split("-", 1)
        try:
            start_port = int(start)
            end_port = int(end)
            return start_port <= port <= end_port
        except ValueError:
            return False
    else:
        # Single port
        try:
            return port == int(port_spec)
        except ValueError:
            return False
