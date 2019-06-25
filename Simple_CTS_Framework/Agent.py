from abc import *
from DataModels import *


class Agent(metaclass=ABCMeta):
    def __init__(self):
        pass

    @abstractmethod
    def _get_current_state(self):
        pass

    @abstractmethod
    def _determine_available_techniques(self):
        pass

    @abstractmethod
    def _do_planning(self):
        pass

    @abstractmethod
    def _use_technique(self):
        pass

    @abstractmethod
    def _update_state(self):
        pass

    @abstractmethod
    def run(self):
        pass


class RedAgent(Agent):
    network_topology = None
    file_list = None

    def __init__(self, network_topology=None, file_list=None):
        super().__init__()
        self.network_topology = network_topology
        self.file_list = file_list

    def _get_current_state(self):
        pass

    def _determine_available_techniques(self):
        pass

    def _do_planning(self):
        pass

    def _use_technique(self):
        pass

    def _update_state(self):
        pass

    def run(self):
        pass


class BlueAgent(Agent):
    def _get_current_state(self):
        pass

    def _determine_available_techniques(self):
        pass

    def _do_planning(self):
        pass

    def _use_technique(self):
        pass

    def _update_state(self):
        pass

    def run(self):
        pass


if __name__ == "__main__":
    def make_test_topology():
        node1 = Node('test_kali', '192.168.61.129', OS('Linux'), [Port(23)])
        node2 = Node('none_sys', 'xxx.xxx.xxx.xxx', OS('Linux'))

        edge1 = Edge(node1, node2, [Port(23)])
        print(edge1)


    make_test_topology()

    agent1 = RedAgent()
    print(agent1.network_topology)

    agent2 = RedAgent()
    print(agent2.network_topology)
