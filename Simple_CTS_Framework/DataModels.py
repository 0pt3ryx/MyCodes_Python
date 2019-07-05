class Port:
    def __init__(self, port_number=0):
        if self._is_valid_number(port_number) is False:
            assert False
        self.number = port_number

    def _is_valid_number(self, port_number):
        if 0 <= port_number <= 65535:
            return True
        else:
            return False

    def __repr__(self):
        represent = 'Port Number: ' + str(self.number)
        return represent


class OS:
    _valid_os = {'Linux', 'Windows'}

    def __init__(self, os_name):
        if self._is_valid_os_name(os_name) is False:
            assert False
        self.name = os_name

    def _is_valid_os_name(self, os_name):
        if os_name in self._valid_os:
            return True
        else:
            return False

    def __repr__(self):
        represent = 'OS: ' + self.name
        return represent


class Node:
    def __init__(self, system_name, ip_addr, os, opened_ports=None, credentials=None, files=None, vulnerabilities=None):
        if self._is_valid_types(system_name, ip_addr, os, opened_ports, credentials, files, vulnerabilities) is False:
            assert False
        self.system_name = system_name
        self.ip_addr = ip_addr
        self.os = os
        self.opened_ports = opened_ports
        self.credentials = credentials
        self.files = files

    def _is_valid_types(self, system_name, ip_addr, os, opened_ports, credentials, files, vulnerabilities):
        """
        :param system_name:
        :param ip_addr:
        """
        if isinstance(os, OS) is False:
            return False
        if isinstance(opened_ports, list) is True:
            for port in opened_ports:
                if isinstance(port, Port) is False:
                    return False
        if isinstance(credentials, list) is True:
            for credential in credentials:
                if isinstance(credential, Credential) is False:
                    return False
        if isinstance(files, list) is True:
            for file in files:
                if isinstance(file, File) is False:
                    return False
        if isinstance(vulnerabilities, list) is True:
            for vulnerability in vulnerabilities:
                if isinstance(vulnerability, Vulnerability) is False:
                    return False
        return True

    def __repr__(self):
        represent = 'System Name: ' + self.system_name + '\n'
        represent += 'IP: ' + self.ip_addr + '\n'
        represent += self.os.__repr__() + '\n'
        represent += 'Opened Ports: ['
        if self.opened_ports is not None:
            for port in self.opened_ports:
                represent += str(port.number) + ', '
        represent += ']\n'
        represent += 'Credentials: ' + '\n'
        represent += 'Files: ' + '\n'
        represent += 'Vulnerabilities: ' + '\n'
        return represent


class Edge:
    def __init__(self, src_node, dst_node, access_ports=None):
        if self._is_valid_types(src_node, dst_node, access_ports) is False:
            assert False
        self.src_node = src_node
        self.dst_node = dst_node
        self.access_ports = access_ports

    def _is_valid_types(self, src_node, dst_node, access_ports):
        if isinstance(src_node, Node) is False or isinstance(dst_node, Node) is False:
            return False
        if isinstance(access_ports, list) is True:
            for port in access_ports:
                if isinstance(port, Port) is False:
                    return False
        return True


    def __repr__(self):
        represent = 'Source Node: ' + self.src_node.system_name + '\n'
        represent += 'Destination Node: ' + self.dst_node.system_name + '\n'
        return represent


class Credential:
    def __init__(self, user_name, password, admin=False):
        self.user_name = user_name
        self.password = password
        self.admin = admin


class File:
    _valid_file_type = {'exe'}

    def __init__(self, file_name, file_path, file_type):
        if self._is_valid_types(file_name, file_path, file_type) is False:
            assert False
        self.file_name = file_name
        self.file_path = file_path
        self.file_type = file_type

    def _is_valid_types(self, file_name, file_path, file_type):
        """
        :param file_name:
        :param file_path:
        """
        if file_type in self._valid_file_type:
            return True
        else:
            return False

    def __repr__(self):
        represent = 'File Name: ' + self.file_name + '\n'
        represent += 'File Path: ' + self.file_path + '\n'
        represent += 'File Type: ' + self.file_type
        return represent


class Vulnerability:
    def __init__(self):
        pass


class NetworkTopology:
    def __init__(self, nodes, edges):
        if self._is_valid_types(nodes, edges) is False:
            assert False
        self.nodes = nodes
        self.edges = edges

    def _is_valid_types(self, nodes, edges):
        for node in nodes:
            if isinstance(node, Node) is False:
                return False
        for edge in edges:
            if isinstance(edge, Edge) is False:
                return False
        return True


class Technique:
    def __init__(self, id, use_team, score, preconditions, commands, success_condition, effect):
        # TODO - Check validation
        self.id = id
        self.use_team = use_team
        self.score = score
        self.preconditions = preconditions
        self.commands = commands
        self.success_condition = success_condition
        self.effect = effect

    def is_success(self, printed_string):
        # TODO
        if self.success_condition in printed_string:
            return True
        else:
            return False


if __name__ == "__main__":

    t_os = OS('Linux')
    t_port = Port(3000)
    t_node1 = Node('Attacker', '163.152.127.1', t_os, [t_port])
    #print(t_node1.system_name)
    #print(t_node1.ip_addr)
    #print(t_node1.os.name)
    #print(t_node1.opened_ports[0].number)
    #print(t_node1.credentials)

    # print(t_node1)
    t_file = File('hello.exe', 'D:\\test\\dir1', 'exe')
    print(t_file)
