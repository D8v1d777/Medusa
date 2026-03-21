from abc import ABC, abstractmethod
from pentkit.core.session import Session

class PluginBase(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the plugin."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of the plugin."""
        pass

    @abstractmethod
    async def run(self, session: Session):
        """Run the plugin logic."""
        pass
