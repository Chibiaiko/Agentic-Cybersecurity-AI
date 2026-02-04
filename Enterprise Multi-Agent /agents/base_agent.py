from abc import ABC, abstractmethod
from typing import Any, Dict

class BaseAgent(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the agent's logic.
        :param context: Shared context dictionary containing results from previous agents.
        :return: Updated context or specific results.
        """
        pass
