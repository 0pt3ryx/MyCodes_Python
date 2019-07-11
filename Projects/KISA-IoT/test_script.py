import dpkt

Src_file_name = 'D:\\tasks\\Projects\\KISA IoT 2년차 (2019년 1월 ~)' \
                '\\네트워크패킷수집\\EZVIZ_dump_from_n604s\\refresh.pcap'

ETH_TYPE_IP = dpkt.ethernet.ETH_TYPE_IP
ETH_TYPE_IP6 = dpkt.ethernet.ETH_TYPE_IP6
IP_PROTO_TCP = dpkt.ip.IP_PROTO_TCP
IP_PROTO_UDP = dpkt.ip.IP_PROTO_UDP
IP_PROTO_ICMP = dpkt.ip.IP_PROTO_ICMP


def load_and_read_pcap(file_name):
    src_file = open(file_name, 'rb')

    if Src_file_name.find('.pcapng') >= 0:
        read_instance = dpkt.pcapng.Reader(src_file)
    elif Src_file_name.find('.pcap') >= 0:
        read_instance = dpkt.pcap.Reader(src_file)
    else:
        raise NotImplementedError

    return read_instance


def do_test(pcap_instance):

    packet_idx = 0
    for ts, buf in pcap_instance:
        packet_idx += 1
        ether_level = dpkt.ethernet.Ethernet(buf)
        ip_level = ether_level.data

        if ether_level.type == ETH_TYPE_IP:
            pass
        elif ether_level.type == ETH_TYPE_IP6:
            pass
        else:
            print("### Warning - this packet is not an IP packet. ###")
            print("\tIndex: %d" % packet_idx)
            print("\tEthernet type: 0x%04x" % ether_level.type)
            continue

        print(type(ip_level.data.sport))
        print(ip_level.data.dport)
        if ip_level.p == IP_PROTO_TCP:
            tcp_level = ip_level.data
            # print("{0:b}".format(int(tcp_level.flags)).zfill(8))
            # print(hex(tcp_level.flags))
            pass
        elif ip_level.p == IP_PROTO_UDP:
            pass
        else:
            print("### Warning - its protocol is not tcp or udp. ###")
            pass


class tc(object):
    def __init__(self, name, length, age):
        self.name = name
        self.length = length
        self.age = age


def t_func(target_dict):
    target_dict['a']['1'] = 1000
    target_dict['b'] = 10
    target_dict['a']['3'] = 33


Pcap_instance = load_and_read_pcap(Src_file_name)
do_test(Pcap_instance)

#from dpkt.ip import *
# ip = IP(id=0, src=b'\x01\x02\x03\x04', dst=b'\x01\x02\x03\x04', p=17)
# print(ip.data
