from abc import *
from DataModels import *
import asyncio, telnetlib3


class Agent(metaclass=ABCMeta):
    def __init__(self):
        pass

    @abstractmethod
    def _get_current_state(self, network_topology, file_list, goal, techniques):
        pass

    @abstractmethod
    def _determine_available_techniques(self):
        pass

    @abstractmethod
    def _do_planning(self, technique_set):
        pass

    @abstractmethod
    def _use_technique(self, technique):
        pass

    @abstractmethod
    def _update_state(self, effect):
        pass

    @abstractmethod
    def run(self, network_topology, file_list, goal, techniques):
        pass


class RedAgent(Agent):
    network_topology = None
    file_list = None
    goal = None
    techniques = None
    sleep_tick = 2

    def __init__(self):
        super().__init__()

    def _get_current_state(self, network_topology, file_list, goal, techniques):
        RedAgent.network_topology = network_topology
        RedAgent.file_list = file_list
        RedAgent.goal = goal
        RedAgent.techniques = techniques

    def _is_goal_achieved(self):
        return True

    def _determine_available_techniques(self):
        return []

    def _do_planning(self, technique_set):
        return []

    def _use_technique(self, technique):
        # Try

        return None, None

    def _update_state(self, effect):
        pass

    def run(self, network_topology, file_list, goal, techniques):
        self._get_current_state(network_topology, file_list, goal, techniques)

        while self._is_goal_achieved() is False:
            techniques_set = self._determine_available_techniques()

            # If there is no available technique
            if len(techniques_set) == 0:
                return

            technique_list = self._do_planning(techniques_set)
            for technique in technique_list:
                result, effect = self._use_technique(technique)
                self._update_state(effect)

                if result is False:
                    continue
                else:
                    break

    # 시스템에 접근
    def _access_system(self):
        pass

    async def _telnet_shell(self, reader, writer):
        user_name = self.network_topology.nodes[0].credentials[0].user_name
        password = self.network_topology.nodes[0].credentials[0].password

        outp = await reader.read(1024)
        print(outp, flush=True)

        writer.write(user_name + '\n')
        await asyncio.sleep(2)
        writer.write(password + '\n')
        await asyncio.sleep(2)
        writer.write('cd root' + '\n' + 'ls -al' + '\n')
        await asyncio.sleep(2)
        outp = await reader.read(4096)
        print(outp, flush=True)

        # EOF
        print()

    async def _access_through_telnet(self, node):
        reader, writer = await telnetlib3.open_connection(node.ip_addr, 23, shell=self._telnet_shell)
        await writer.protocol.waiter_closed


class BlueAgent(Agent):
    def _get_current_state(self, network_topology, file_list, goal, techniques):
        pass

    def _determine_available_techniques(self):
        pass

    def _do_planning(self, technique_set):
        pass

    def _use_technique(self, technique):
        pass

    def _update_state(self, effect):
        pass

    def run(self, network_topology, file_list, goal, techniques):
        pass


if __name__ == "__main__":
    def make_test_topology():
        node1 = Node('test_kali', '192.168.61.129', OS('Linux'),
                     [Port(23)],
                     [Credential('testuser', 'test1234', False)])
        node2 = Node('none_sys', 'xxx.xxx.xxx.xxx', OS('Linux'))

        edge1 = Edge(node1, node2, [Port(23)])
        print(edge1)

        test_network_topology = NetworkTopology([node1, node2], [edge1])
        return test_network_topology


    def make_test_file_list():
        file1 = File('test_file1', 'D:\\path1', 'exe')
        file2 = File('test_file2', 'D:\\path2', 'exe')

        return [file1, file2]


    network_topology = make_test_topology()
    file_list = make_test_file_list()

    agent1 = RedAgent()
    print(RedAgent.network_topology)
    agent1.run(network_topology, file_list, None, None)

    first_node = network_topology.nodes[0]
    loop = asyncio.get_event_loop()
    coro = agent1._access_through_telnet(first_node)
    loop.run_until_complete(coro)
