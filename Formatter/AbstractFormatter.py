from abc import ABC, abstractmethod


class AbstractFormatter(ABC):

    @abstractmethod
    def format(self, value):
        pass

    @abstractmethod
    def parse(self, value):
        pass
    