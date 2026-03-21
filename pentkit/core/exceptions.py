class PentkitError(Exception):
    """Base class for all pentkit exceptions."""
    pass

class OutOfScopeError(PentkitError):
    """Raised when an action is attempted on an out-of-scope target."""
    def __init__(self, target: str, module: str = "unknown"):
        self.target = target
        self.module = module
        super().__init__(f"Out of scope attempt: target={target}, module={module}")
