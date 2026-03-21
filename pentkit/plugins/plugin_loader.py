import importlib.metadata
from typing import List, Dict, Type
from pentkit.plugins.plugin_base import PluginBase
from pentkit.core.logger import get_module_logger

logger = get_module_logger("plugins.loader")

class PluginLoader:
    def __init__(self, entry_point_group: str = "pentkit.plugins"):
        self.entry_point_group = entry_point_group
        self.plugins: Dict[str, PluginBase] = {}

    def discover_plugins(self):
        """Discover and load plugins from entry points."""
        try:
            eps = importlib.metadata.entry_points().select(group=self.entry_point_group)
            for ep in eps:
                try:
                    plugin_class: Type[PluginBase] = ep.load()
                    plugin_instance = plugin_class()
                    self.plugins[plugin_instance.name] = plugin_instance
                    logger.info(f"Loaded plugin: {plugin_instance.name}")
                except Exception as e:
                    logger.error(f"Failed to load plugin from {ep.name}: {e}")
        except Exception as e:
            logger.debug(f"Plugin discovery failed: {e}")
        return self.plugins

    def get_plugin(self, name: str) -> Optional[PluginBase]:
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict[str, str]]:
        return [
            {"name": p.name, "description": p.description}
            for p in self.plugins.values()
        ]
