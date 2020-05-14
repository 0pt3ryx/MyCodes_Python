import dpkt
import copy
import csv
import pickle

# Src_file_name = 'D:\\VM\\shared\\00_frag_udp.pcapng'

"""
Src_file_name = 'D:\\tasks\\Projects\\KISA IoT 2년차 (2019년 1월 ~)\\' \
                '네트워크패킷수집\\ezviz_traffic_sample\\190711_3_NUGU_Scanning_HOST+PORT_total-dec.pcap'
"""
# Src_file_name = '.\\source\\190520_1_benign_total-dec.pcap'
# Exported_file_name = '.\\feature_extracted.csv'

ETH_TYPE_IP = dpkt.ethernet.ETH_TYPE_IP
ETH_TYPE_IP6 = dpkt.ethernet.ETH_TYPE_IP6
ETH_TYPE_ARP = dpkt.ethernet.ETH_TYPE_ARP
IP_PROTO_TCP = dpkt.ip.IP_PROTO_TCP
IP_PROTO_UDP = dpkt.ip.IP_PROTO_UDP
IP_PROTO_ICMP = dpkt.ip.IP_PROTO_ICMP
IP_PROTO_ICMP6 = dpkt.ip.IP_PROTO_ICMP6

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20
TH_ECE = 0x40
TH_CWR = 0x80

TIME_WINDOW_SIZE_CNT = 100
TIME_WINDOW_SIZE_SEC = 5
DECIMAL_PRECISION = 6

Packet_idx = 0
"""
Field_symbol = dict()
Field_symbol['protocol_type'] = ['tcp', 'udp', 'icmp']
Field_symbol['flag'] = ['OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH']
"""
Fragment_buffer = dict()
Field_names = ['idx', 'timestamp', 'src_ether', 'dst_ether', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 's_mac_addr',
               't_mac_addr', 'protocol_type', 'tl_data_len', 'flag', 'num_of_frags', 'src_dst_same', 'same_sip_pkt_cnt',
               'same_dip_pkt_cnt', 'same_sip_sport_pkt_cnt', 'same_dip_dport_pkt_cnt', 'same_sip_pkt_dip_cnt',
               'same_dip_pkt_sip_cnt', 'same_src_dst_pkt_sport_cnt', 'same_src_dst_pkt_dport_cnt',
               'arp_op', 'icmp_type', 'icmp_code', 'same_sip_src_bytes', 'same_dip_dst_bytes', 'same_sip_icmp_ratio',
               'same_dip_icmp_ratio', 'same_sip_syn_ratio', 'same_dip_syn_ratio', 'same_sip_syn_ack_diff_cnt',
               'same_dip_syn_ack_diff_cnt']


def load_and_read_pcap(file_name):
    src_file = open(file_name, 'rb')

    if file_name.find('.pcapng') >= 0:
        read_instance = dpkt.pcapng.Reader(src_file)
    elif file_name.find('.pcap') >= 0:
        read_instance = dpkt.pcap.Reader(src_file)
    else:
        raise NotImplementedError

    return read_instance


def _convert_addr(addr_bytes, protocol='IPv4'):
    result_addr = ''

    if protocol == 'IPv4' and type(addr_bytes) is bytes and len(addr_bytes) == 4:
        for addr_idx in range(4):
            temp_str = ".%d" % addr_bytes[addr_idx]
            result_addr += temp_str
        return result_addr[1:]
    elif protocol == 'IPv6' and type(addr_bytes) is bytes and len(addr_bytes) == 16:
        for addr_idx in range(16):
            temp_str = ''
            if addr_idx % 2 == 0:
                temp_str += ':'
            temp_str += "%02x" % (addr_bytes[addr_idx])
            result_addr += temp_str
        return result_addr[1:]
    else:
        raise Exception('@ Error\n\tInvalid parameter - convert_addr()')


def _convert_mac_addr(mac_addr_bytes, mac_addr_length=6):
    result_addr = ''

    if type(mac_addr_bytes) is bytes and len(mac_addr_bytes) == mac_addr_length:
        for addr_idx in range(mac_addr_length):
            temp_str = ":%x" % mac_addr_bytes[addr_idx]
            result_addr += temp_str
    else:
        raise Exception('@ Error\n\tInvalid parameter - conveert_mac_addr()')

    return result_addr[1:]


def _extract_protocol_type(ip_packet):
    if ip_packet.p == IP_PROTO_TCP:
        return 'TCP'
    elif ip_packet.p == IP_PROTO_UDP:
        return 'UDP'
    elif ip_packet.p == IP_PROTO_ICMP:
        return 'ICMP'
    else:
        # raise NotImplementedError
        return 'Not_Implemented'


def _extract_service():
    # TODO - Need to implement
    return 'No_service'


def _extract_ctrl_flag(ip_packet):
    if ip_packet.p == IP_PROTO_TCP:
        result_flag_list = list()
        ctrl_flag = ip_packet.data.flags

        if ctrl_flag & TH_FIN:
            result_flag_list.append('FIN')
        if ctrl_flag & TH_SYN:
            result_flag_list.append('SYN')
        if ctrl_flag & TH_RST:
            result_flag_list.append('RST')
        if ctrl_flag & TH_PUSH:
            result_flag_list.append('PSH')
        if ctrl_flag & TH_ACK:
            result_flag_list.append('ACK')
        if ctrl_flag & TH_URG:
            result_flag_list.append('URG')
        if ctrl_flag & TH_ECE:
            result_flag_list.append('ECE')
        if ctrl_flag & TH_CWR:
            result_flag_list.append('CWR')

        return result_flag_list
    else:
        return 'No_flag'


def _extract_transport_layer_data_len(ip_packet):
    try:
        result = ip_packet.data.data.__len__()
    except AttributeError:
        result = ip_packet.data.__len__()

    return result


def _reassemble_packet(frag_id):
    # 1. Sorting fragments by order
    Fragment_buffer[frag_id]['packets'].sort(key=lambda pkt: dpkt.ethernet.Ethernet(pkt).data.offset)

    # 2. Temporarily assemble packet
    tmp_assembled_packet = None
    for frag in Fragment_buffer[frag_id]['packets']:
        if tmp_assembled_packet is None:
            tmp_assembled_packet = bytes(frag)  # Including ethernet header and ip header
        else:
            tmp_assembled_packet += bytes(dpkt.ethernet.Ethernet(frag).data.data)   # Including only ip data

    # 3. Modifying ip header length
    packet_front_part = copy.deepcopy(tmp_assembled_packet[:6+6+2+2])
    packet_rear_part = copy.deepcopy(tmp_assembled_packet[6+6+2+2+2:])
    ip_length = 2 + 2 + len(packet_rear_part)   # Version, Header Length (2 bytes) + IP Length (2 bytes) + The rest

    assembled_packet = packet_front_part + bytes(ip_length.to_bytes(2, byteorder='big')) + packet_rear_part
    # assembled_packet = dpkt.ethernet.Ethernet(assembled_packet)

    del tmp_assembled_packet

    Fragment_buffer[frag_id]['reassembled'] = assembled_packet


# Return Value
# False, False  : Not fragmentation
# False, True   : All fragments has arrived
# True, False   : Fragmentation
def _is_fragment(packet, ip_level):
    if ip_level.df:     # Not fragmented
        if ip_level.mf or ip_level.offset > 0:
            print(Packet_idx)
            print('DF is set, but mf is also set')
            return True, False

        return False, False
    else:               # Fragmented
        if not (ip_level.id in Fragment_buffer):    # If this is the first fragment
            Fragment_buffer[ip_level.id] = dict()
            Fragment_buffer[ip_level.id]['packets'] = list()
            Fragment_buffer[ip_level.id]['tot_len'] = 65536
            Fragment_buffer[ip_level.id]['acc_len'] = 0
            Fragment_buffer[ip_level.id]['num_of_frags'] = 0

        if ip_level.mf == 0:    # If this is the last fragmentation
            try:
                assert ip_level.len - ip_level.hl * 4 == ip_level.data.__len__()
            except AssertionError:
                print(Packet_idx)
                print('Last fragmentation has arrived but has an exception.')
            Fragment_buffer[ip_level.id]['tot_len'] = ip_level.offset + ip_level.len - ip_level.hl * 4

        Fragment_buffer[ip_level.id]['packets'].append(packet)
        Fragment_buffer[ip_level.id]['acc_len'] += ip_level.data.__len__()
        Fragment_buffer[ip_level.id]['num_of_frags'] += 1

        # If all of fragments has arrived
        if Fragment_buffer[ip_level.id]['acc_len'] >= Fragment_buffer[ip_level.id]['tot_len']:
            _reassemble_packet(ip_level.id)

            assert Fragment_buffer[ip_level.id]['num_of_frags'] >= 1
            if Fragment_buffer[ip_level.id]['num_of_frags'] == 1:
                Fragment_buffer[ip_level.id]['num_of_frags'] = 0

            return False, True

        return True, False


def _get_num_of_frags(ip_packet):
    if ip_packet.id in Fragment_buffer:
        return Fragment_buffer[ip_packet.id]['num_of_frags']
    else:
        return 0


def _is_valid_protocol(ether_frame):
    eth_type = ether_frame.type

    if eth_type == ETH_TYPE_IP:
        ip_level = ether_frame.data
        try:
            assert ip_level.__len__() >= 20 and hex(bytes(ip_level)[0] >> 4) == hex(0x4)
            assert isinstance(ip_level, dpkt.ip.IP)
        except AssertionError:
            print(Packet_idx)
            # print(hex(bytes(ip_level)[0] >> 4))
            print('Invalid IP header')
            return False
        try:
            if ip_level.p in [IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMP]:
                return True
            else:
                return False
        except AttributeError:
            print(Packet_idx)
            print(hex(ip_level[0]) == hex(0xa3))
            # print(type(hex(0xa3)))
            assert False

    elif eth_type == ETH_TYPE_IP6:
        ip_level = ether_frame.data
        return False
    elif eth_type == ETH_TYPE_ARP:
        return True
    else:
        return False


def _extract_basic_features_arp(ether_frame, new_dict_features):
    arp_level = ether_frame.data
    converted_sender_ip = _convert_addr(arp_level.spa)
    converted_target_ip = _convert_addr(arp_level.tpa)
    if converted_sender_ip == converted_target_ip:
        src_dst_same = 1    # True
    else:
        src_dst_same = 0    # False

    new_dict_features['src_ip'] = converted_sender_ip
    new_dict_features['dst_ip'] = converted_target_ip
    new_dict_features['src_port'] = -1
    new_dict_features['dst_port'] = -1

    new_dict_features['protocol_type'] = 'ARP'
    new_dict_features['tl_data_len'] = -1
    # new_dict_features['service'] = 'No_service'
    new_dict_features['flag'] = 'No_flag'
    # new_dict_features['tcp_win_size'] = -1
    new_dict_features['num_of_frags'] = 0
    new_dict_features['src_dst_same'] = src_dst_same

    new_dict_features['arp_op'] = arp_level.op
    new_dict_features['s_mac_addr'] = _convert_mac_addr(arp_level.sha)
    new_dict_features['t_mac_addr'] = _convert_mac_addr(arp_level.tha)

    new_dict_features['icmp_type'] = -1
    new_dict_features['icmp_code'] = -1

    return


def _extract_basic_features(read_instance):
    global Fragment_buffer, Packet_idx
    packet_list = list()
    parsed_list = list()

    packet_idx = Packet_idx
    # ts: timestamp
    # buf: buffer
    for ts, buf in read_instance:
        packet_idx += 1
        Packet_idx = packet_idx
        try:
            ether_level = dpkt.ethernet.Ethernet(buf)
            ip_level = ether_level.data
        except Exception as e:
            print(e)
            continue

        if _is_valid_protocol(ether_level) is False:
            continue

        # Need to clean code (ARP routine)
        if ether_level.type == ETH_TYPE_ARP:
            new_dict_features = dict()
            new_dict_features['idx'] = packet_idx
            new_dict_features['timestamp'] = ts
            new_dict_features['dst_ether'] = _convert_mac_addr(ether_level.dst, 6)
            new_dict_features['src_ether'] = _convert_mac_addr(ether_level.src, 6)

            whole_packet = buf
            _extract_basic_features_arp(ether_level, new_dict_features)

            parsed_list.append(new_dict_features)
            packet_list.append(whole_packet)
            continue

        # Non-ARP routine
        if ether_level.type == ETH_TYPE_IP:
            is_need_to_remove, is_reassembled = _is_fragment(buf, ip_level)
        elif ether_level.type == ETH_TYPE_IP6:
            is_need_to_remove = False
            is_reassembled = False
        else:
            raise NotImplementedError

        if is_need_to_remove is True:
            continue
        if is_reassembled is True:
            whole_packet = Fragment_buffer[ip_level.id]['reassembled']

            ether_level = dpkt.ethernet.Ethernet(whole_packet)
            ip_level = ether_level.data

            num_of_frags = _get_num_of_frags(ip_level)
            del Fragment_buffer[ip_level.id]
        else:
            whole_packet = buf
            num_of_frags = 0

        if ether_level.type == ETH_TYPE_IP:
            converted_src_ip = _convert_addr(ip_level.src, 'IPv4')
            converted_dst_ip = _convert_addr(ip_level.dst, 'IPv4')
        elif ether_level.type == ETH_TYPE_IP6:
            converted_src_ip = _convert_addr(ip_level.src, 'IPv6')
            converted_dst_ip = _convert_addr(ip_level.dst, 'IPv6')
        else:
            print("### Warning - this packet is not an IP packet. ###")
            print("\tIndex: %d" % packet_idx)
            print("\tEthernet type: 0x%04x" % ether_level.type)
            continue

        protocol_type = _extract_protocol_type(ip_level)
        # service = _extract_service()
        try:
            # flag 뽑는 함수 호출 'SYN' 과 'ACK' 가 들어있음
            ctrl_flag = _extract_ctrl_flag(ip_level)
        except AttributeError as e:
            print(packet_idx)
            print(e)
            continue

        tl_data_len = _extract_transport_layer_data_len(ip_level)

        if converted_src_ip == converted_dst_ip:
            src_dst_same = 1    # True
        else:
            src_dst_same = 0    # False

        new_dict_features = dict()
        new_dict_features['idx'] = packet_idx
        new_dict_features['timestamp'] = ts
        new_dict_features['dst_ether'] = _convert_mac_addr(ether_level.dst, 6)
        new_dict_features['src_ether'] = _convert_mac_addr(ether_level.src, 6)
        new_dict_features['src_ip'] = converted_src_ip
        new_dict_features['dst_ip'] = converted_dst_ip

        if protocol_type == 'TCP' or protocol_type == 'UDP':
            try:
                new_dict_features['src_port'] = ip_level.data.sport
                new_dict_features['dst_port'] = ip_level.data.dport
            except:
                print(Packet_idx)
                assert False
        else:
            new_dict_features['src_port'] = -1
            new_dict_features['dst_port'] = -1

        new_dict_features['protocol_type'] = protocol_type
        new_dict_features['tl_data_len'] = tl_data_len
        # new_dict_features['service'] = service
        # list형식이다.
        new_dict_features['flag'] = ctrl_flag

        """
        if protocol_type == 'TCP':
            new_dict_features['tcp_win_size'] = ip_level.data.win
        else:
            new_dict_features['tcp_win_size'] = -1
        """

        new_dict_features['num_of_frags'] = num_of_frags
        new_dict_features['src_dst_same'] = src_dst_same

        new_dict_features['arp_op'] = -1
        new_dict_features['s_mac_addr'] = -1
        new_dict_features['t_mac_addr'] = -1

        if protocol_type == 'ICMP':
            new_dict_features['icmp_type'] = ip_level.data.type
            new_dict_features['icmp_code'] = ip_level.data.code
        else:
            new_dict_features['icmp_type'] = -1
            new_dict_features['icmp_code'] = -1

        parsed_list.append(new_dict_features)
        packet_list.append(whole_packet)

    assert len(packet_list) == len(parsed_list)
    return packet_list, parsed_list


# Clear the time window stat dictionary
def _clear_time_window_stat_dict(time_window_sec_stat):
    for src_ip in time_window_sec_stat['forward'].keys():
        for dst_ip in time_window_sec_stat['forward'][src_ip]['dst_ips'].keys():
            for dst_port in time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'].keys():
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port].clear()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'].clear()
            for src_port in time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'].keys():
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port].clear()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'].clear()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip].clear()
        time_window_sec_stat['forward'][src_ip]['dst_ips'].clear()

        for src_port in time_window_sec_stat['forward'][src_ip]['ports'].keys():
            time_window_sec_stat['forward'][src_ip]['ports'][src_port].clear()
        time_window_sec_stat['forward'][src_ip]['ports'].clear()

        time_window_sec_stat['forward'][src_ip].clear()
    time_window_sec_stat['forward'].clear()

    for dst_ip in time_window_sec_stat['backward'].keys():
        time_window_sec_stat['backward'][dst_ip].clear()
    time_window_sec_stat['backward'].clear()


# Clean up Source info and Destination info from stat
def _clean_time_window_stat_dict(time_window_sec_stat, packet_parsed_head):
    head_src_ip = packet_parsed_head[1]['src_ip']
    head_dst_ip = packet_parsed_head[1]['dst_ip']
    head_src_port = packet_parsed_head[1]['src_port']
    head_dst_port = packet_parsed_head[1]['dst_port']
    head_protocol_type = packet_parsed_head[1]['protocol_type']
    head_flag_list = packet_parsed_head[1]['flag']
    head_pkt_length = len(packet_parsed_head[0])

    # Clean up Source info and Destination info from stat
    time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]['num_pkts'] -= 1
    if time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]['num_pkts'] <= 0:
        time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port].clear()
        del time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]
    else:
        time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]['tot_bytes'] -= head_pkt_length
        if head_protocol_type == 'ICMP':
            time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]['num_icmps'] -= 1
        assert time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]['num_icmps'] >= 0
        if 'SYN' in head_flag_list:
            time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]['num_syn'] -= 1
        assert time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]['num_syn'] >= 0
        if 'ACK' in head_flag_list:
            time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]['num_ack'] -= 1
        assert time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts'][head_dst_port]['num_ack'] >= 0

    time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]['num_pkts'] -= 1
    if time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]['num_pkts'] <= 0:
        time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port].clear()
        del time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]
    else:
        time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]['tot_bytes'] -= head_pkt_length
        if head_protocol_type == 'ICMP':
            time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]['num_icmps'] -= 1
        assert time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]['num_icmps'] >= 0
        if 'SYN' in head_flag_list:
            time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]['num_syn'] -= 1
        assert time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]['num_syn'] >= 0
        if 'ACK' in head_flag_list:
            time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]['num_ack'] -= 1
        assert time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts'][head_src_port]['num_ack'] >= 0

    if len(time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['sPorts']) == 0 and \
            len(time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]['dPorts']) == 0:
        time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip].clear()
        del time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]

        time_window_sec_stat['forward'][head_src_ip]['ports'][head_src_port].remove(head_dst_ip)
        if len(time_window_sec_stat['forward'][head_src_ip]['ports'][head_src_port]) == 0:
            del time_window_sec_stat['forward'][head_src_ip]['ports'][head_src_port]

        time_window_sec_stat['backward'][head_dst_ip].remove(head_src_ip)
        if len(time_window_sec_stat['backward'][head_dst_ip]) == 0:
            del time_window_sec_stat['backward'][head_dst_ip]

    if len(time_window_sec_stat['forward'][head_src_ip]['ports']) == 0 and \
            len(time_window_sec_stat['forward'][head_src_ip]['dst_ips']) == 0:
        time_window_sec_stat['forward'][head_src_ip].clear()
        del time_window_sec_stat['forward'][head_src_ip]
    pass


# window 피처 뽑는 함수 (time_window_sec_stat : dict형식의 트리, target_parsed : dict형식의 피처)
def _extract_time_window_features(time_window_sec_stat, target_parsed):
    target_src_ip = target_parsed['src_ip']
    target_dst_ip = target_parsed['dst_ip']
    target_src_port = target_parsed['src_port']
    target_dst_port = target_parsed['dst_port']
    target_protocol_type = target_parsed['protocol_type']

    same_sip_pkt_cnt = 0
    same_dip_pkt_cnt = 0
    same_sip_sport_pkt_cnt = 0
    same_dip_dport_pkt_cnt = 0

    same_sip_pkt_dip_cnt = 0
    same_dip_pkt_sip_cnt = 0
    same_src_dst_pkt_sport_cnt = 0
    same_src_dst_pkt_dport_cnt = 0

    same_sip_src_bytes = 0
    same_dip_dst_bytes = 0
    same_sip_num_icmps = 0  # - 지난 n초간 동일 src IP에서 보낸 패킷 중 ICMP 패킷의 **수**
    same_dip_num_icmps = 0

    same_sip_num_syn = 0    # - 지난 n초간 동일 src IP에서 보낸 패킷 중 SYN 패킷의 **수**
    same_dip_num_syn = 0
    same_sip_num_ack = 0    # - 지난 n초간 동일 src IP에서 보낸 패킷 중 SYN와 ACK 패킷의 차이
    same_dip_num_ack = 0

    if target_src_ip in time_window_sec_stat['forward']:
        for dst_ip in time_window_sec_stat['forward'][target_src_ip]['dst_ips']:
            for src_port in time_window_sec_stat['forward'][target_src_ip]['dst_ips'][dst_ip]['sPorts']:
                if src_port == target_src_port:
                    same_sip_sport_pkt_cnt += time_window_sec_stat['forward'][target_src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_pkts']
                same_sip_pkt_cnt += time_window_sec_stat['forward'][target_src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_pkts']
                same_sip_src_bytes += time_window_sec_stat['forward'][target_src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['tot_bytes']
                same_sip_num_icmps += time_window_sec_stat['forward'][target_src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_icmps']
                same_sip_num_syn += time_window_sec_stat['forward'][target_src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_syn'] # KUB
                same_sip_num_ack += time_window_sec_stat['forward'][target_src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_ack'] # KUB
        same_sip_pkt_dip_cnt = len(time_window_sec_stat['forward'][target_src_ip]['dst_ips'])

        if target_dst_ip in time_window_sec_stat['forward'][target_src_ip]['dst_ips']:
            same_src_dst_pkt_sport_cnt = len(time_window_sec_stat['forward'][target_src_ip]['dst_ips'][target_dst_ip]['sPorts'])
            same_src_dst_pkt_dport_cnt = len(time_window_sec_stat['forward'][target_src_ip]['dst_ips'][target_dst_ip]['dPorts'])
    else:
        pass

    if target_dst_ip in time_window_sec_stat['backward']:
        for src_ip in time_window_sec_stat['backward'][target_dst_ip]:
            try:
                for dst_port in time_window_sec_stat['forward'][src_ip]['dst_ips'][target_dst_ip]['dPorts']:
                    if dst_port == target_dst_port:
                        same_dip_dport_pkt_cnt += time_window_sec_stat['forward'][src_ip]['dst_ips'][target_dst_ip]['dPorts'][dst_port]['num_pkts']
                    same_dip_pkt_cnt += time_window_sec_stat['forward'][src_ip]['dst_ips'][target_dst_ip]['dPorts'][dst_port]['num_pkts']
                    same_dip_dst_bytes += time_window_sec_stat['forward'][src_ip]['dst_ips'][target_dst_ip]['dPorts'][dst_port]['tot_bytes']
                    same_dip_num_icmps += time_window_sec_stat['forward'][src_ip]['dst_ips'][target_dst_ip]['dPorts'][dst_port]['num_icmps']
                    same_dip_num_syn += time_window_sec_stat['forward'][src_ip]['dst_ips'][target_dst_ip]['dPorts'][dst_port]['num_syn'] # KUB
                    same_dip_num_ack += time_window_sec_stat['forward'][src_ip]['dst_ips'][target_dst_ip]['dPorts'][dst_port]['num_ack']  # KUB
            except KeyError as e:
                print(e)
                print(time_window_sec_stat['forward'][src_ip]['dst_ips'])
                raise NotImplementedError
        same_dip_pkt_sip_cnt = len(time_window_sec_stat['backward'][target_dst_ip])
    else:
        pass

    target_parsed['same_sip_pkt_cnt'] = same_sip_pkt_cnt
    target_parsed['same_dip_pkt_cnt'] = same_dip_pkt_cnt

    if target_protocol_type in ['TCP', 'UDP']:
        target_parsed['same_sip_sport_pkt_cnt'] = same_sip_sport_pkt_cnt
        target_parsed['same_dip_dport_pkt_cnt'] = same_dip_dport_pkt_cnt
        target_parsed['same_src_dst_pkt_sport_cnt'] = same_src_dst_pkt_sport_cnt
        target_parsed['same_src_dst_pkt_dport_cnt'] = same_src_dst_pkt_dport_cnt
    else:
        target_parsed['same_sip_sport_pkt_cnt'] = -1
        target_parsed['same_dip_dport_pkt_cnt'] = -1
        target_parsed['same_src_dst_pkt_sport_cnt'] = -1
        target_parsed['same_src_dst_pkt_dport_cnt'] = -1

    target_parsed['same_sip_pkt_dip_cnt'] = same_sip_pkt_dip_cnt
    target_parsed['same_dip_pkt_sip_cnt'] = same_dip_pkt_sip_cnt

    # TODO - Add more features
    target_parsed['same_sip_src_bytes'] = same_sip_src_bytes
    target_parsed['same_dip_dst_bytes'] = same_dip_dst_bytes
    if same_sip_pkt_cnt == 0:
        target_parsed['same_sip_icmp_ratio'] = 0
        target_parsed['same_sip_syn_ratio'] = 0  # KUB
    else:
        target_parsed['same_sip_icmp_ratio'] = same_sip_num_icmps / same_sip_pkt_cnt
        target_parsed['same_sip_syn_ratio'] = same_sip_num_syn / same_sip_pkt_cnt  # KUB
    if same_dip_pkt_cnt == 0:
        target_parsed['same_dip_icmp_ratio'] = 0
        target_parsed['same_dip_syn_ratio'] = 0  # KUB
    else:
        target_parsed['same_dip_icmp_ratio'] = same_dip_num_icmps / same_dip_pkt_cnt
        target_parsed['same_dip_syn_ratio'] = same_dip_num_syn / same_dip_pkt_cnt  # KUB
    target_parsed['same_sip_syn_ack_diff_cnt'] = abs(same_sip_num_ack - same_sip_num_syn)
    target_parsed['same_dip_syn_ack_diff_cnt'] = abs(same_dip_num_ack - same_dip_num_syn)

    return


# window tree update & window 피처 뽑는 함수 호출
def _extract_advanced_features(packet_list, parsed_list, time_window_sec_stat, packet_parsed_in_time_window_sec):
    if len(packet_parsed_in_time_window_sec) > 0:
        head_ts = packet_parsed_in_time_window_sec[0][1]['timestamp']
        tail_ts = parsed_list[0]['timestamp']
        if tail_ts - head_ts < 0:
            print('**Invalid Order. Delete.**')
            _clear_time_window_stat_dict(time_window_sec_stat)
            packet_parsed_in_time_window_sec.clear()

    packet_parsed_list = zip(packet_list, parsed_list)

    # 날것의 패킷이 packet, 그걸 쓰는 요소만 dict형식으로 저장한게 parsed
    for packet, parsed in packet_parsed_list:
        # window 피처 뽑는 함수 호출 OUT은 parsed라는 dict에 업데이트
        _extract_time_window_features(time_window_sec_stat, parsed)
        packet_parsed_in_time_window_sec.append((packet, parsed))

        head_ts = packet_parsed_in_time_window_sec[0][1]['timestamp']
        tail_ts = parsed['timestamp']
        while tail_ts - head_ts > TIME_WINDOW_SIZE_SEC:
            _clean_time_window_stat_dict(time_window_sec_stat, packet_parsed_in_time_window_sec[0])

            # Move the head of the time window
            head_ts = packet_parsed_in_time_window_sec[1][1]['timestamp']
            # Clean up the old head of the time window
            del packet_parsed_in_time_window_sec[0]

        src_ip = parsed['src_ip']
        dst_ip = parsed['dst_ip']
        src_port = parsed['src_port']
        dst_port = parsed['dst_port']
        protocol_type = parsed['protocol_type']
        flag_list = parsed['flag']  # kub
        pkt_length = len(packet)

        if src_ip not in time_window_sec_stat['forward']:
            time_window_sec_stat['forward'][src_ip] = dict()
            time_window_sec_stat['forward'][src_ip]['ports'] = dict()
            time_window_sec_stat['forward'][src_ip]['ports'][src_port] = set()
            time_window_sec_stat['forward'][src_ip]['ports'][src_port].add(dst_ip)

            time_window_sec_stat['forward'][src_ip]['dst_ips'] = dict()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip] = dict()

            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'] = dict()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port] = dict()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_pkts'] = 1
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['tot_bytes'] = pkt_length
            if protocol_type == 'ICMP':
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_icmps'] = 1
            else:
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_icmps'] = 0
            if 'SYN' in flag_list: # kub
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_syn'] = 1
            else:
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_syn'] = 0
            if 'ACK' in flag_list: # kub
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_ack'] = 1
            else:
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_ack'] = 0

            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'] = dict()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port] = dict()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_pkts'] = 1
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['tot_bytes'] = pkt_length
            if protocol_type == 'ICMP':
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_icmps'] = 1
            else:
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_icmps'] = 0
            if 'SYN' in flag_list: # kub
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_syn'] = 1
            else:
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_syn'] = 0
            if 'ACK' in flag_list: # kub
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_ack'] = 1
            else:
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_ack'] = 0
        else:
            if src_port not in time_window_sec_stat['forward'][src_ip]['ports']:
                time_window_sec_stat['forward'][src_ip]['ports'][src_port] = set()
                time_window_sec_stat['forward'][src_ip]['ports'][src_port].add(dst_ip)
            else:
                time_window_sec_stat['forward'][src_ip]['ports'][src_port].add(dst_ip)

            if dst_ip not in time_window_sec_stat['forward'][src_ip]['dst_ips']:
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip] = dict()
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'] = dict()
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port] = dict()
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_pkts'] = 1
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['tot_bytes'] = pkt_length
                if protocol_type == 'ICMP':
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_icmps'] = 1
                else:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_icmps'] = 0
                if 'SYN' in flag_list:  # kub
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_syn'] = 1
                else:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_syn'] = 0
                if 'ACK' in flag_list:  # kub
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_ack'] = 1
                else:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_ack'] = 0

                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'] = dict()
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port] = dict()
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_pkts'] = 1
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['tot_bytes'] = pkt_length
                if protocol_type == 'ICMP':
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_icmps'] = 1
                else:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_icmps'] = 0
                if 'SYN' in flag_list:  # kub
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_syn'] = 1
                else:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_syn'] = 0
                if 'ACK' in flag_list:  # kub
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_ack'] = 1
                else:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_ack'] = 0
            else:
                if dst_port not in time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts']:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port] = dict()
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_pkts'] = 1
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['tot_bytes'] = pkt_length
                    if protocol_type == 'ICMP':
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_icmps'] = 1
                    else:
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_icmps'] = 0
                    if 'SYN' in flag_list:  # kub
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_syn'] = 1
                    else:
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_syn'] = 0
                    if 'ACK' in flag_list:  # kub
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_ack'] = 1
                    else:
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_ack'] = 0
                else:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_pkts'] += 1
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['tot_bytes'] += pkt_length
                    if protocol_type == 'ICMP':
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_icmps'] += 1
                    if 'SYN' in flag_list: # kub
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_syn'] += 1
                    if 'ACK' in flag_list: # kub
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['dPorts'][dst_port]['num_ack'] += 1

                if src_port not in time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts']:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port] = dict()
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_pkts'] = 1
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['tot_bytes'] = pkt_length
                    if protocol_type == 'ICMP':
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_icmps'] = 1
                    else:
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_icmps'] = 0
                    if 'SYN' in flag_list:  # kub
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_syn'] = 1
                    else:
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_syn'] = 0
                    if 'ACK' in flag_list:  # kub
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_ack'] = 1
                    else:
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_ack'] = 0
                else:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_pkts'] += 1
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['tot_bytes'] += pkt_length
                    if protocol_type == 'ICMP':
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_icmps'] += 1
                    if 'SYN' in flag_list: # kub
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_syn'] += 1
                    if 'ACK' in flag_list: # kub
                        time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]['sPorts'][src_port]['num_ack'] += 1

        if dst_ip not in time_window_sec_stat['backward']:
            time_window_sec_stat['backward'][dst_ip] = set()
        time_window_sec_stat['backward'][dst_ip].add(src_ip)

    return parsed_list


def parse_file(read_instance, time_window_sec_stat, packet_parsed_in_time_window_sec):
    packet_list, parsed_list = _extract_basic_features(read_instance)
    parsed_list = _extract_advanced_features(packet_list, parsed_list,
                                             time_window_sec_stat, packet_parsed_in_time_window_sec)
    return parsed_list


def export_feature_data(parsed_list, export_file_name):
    with open(export_file_name, 'wt', newline='\n') as dst_file:
        writer = csv.DictWriter(dst_file, fieldnames=Field_names)
        writer.writeheader()
        writer.writerows(parsed_list)


def extract_feature(pcap_file_name, export_file_name):
    try:
        with open('../pickled_time_window_sec_stat', 'rb') as pickle_file:
            time_window_sec_stat = pickle.load(pickle_file)
    except FileNotFoundError as ex:
        print(ex)
        time_window_sec_stat = {}
        time_window_sec_stat['forward'] = {}
        time_window_sec_stat['backward'] = {}
        print('\tInstead, new dictionary created')

    try:
        with open('../pickled_packet_parsed_in_time_window_sec', 'rb') as pickle_file:
            packet_parsed_in_time_window_sec = pickle.load(pickle_file)
    except FileNotFoundError as ex:
        print(ex)
        # dict['forward'][IP]['port'][src_port][...] = int
        # dict['forward'][IP]['dst_IP'][IP][dst_port][...] = int
        # dict['backward'][IP] = {src_IP1, src_IP2, ...}
        packet_parsed_in_time_window_sec = []
        print('\tInstead, new dictionary created')

    read_pcap_instance = load_and_read_pcap(pcap_file_name)
    parsed_list = parse_file(read_pcap_instance, time_window_sec_stat, packet_parsed_in_time_window_sec)
    export_feature_data(parsed_list, export_file_name)

    with open('../pickled_time_window_sec_stat', 'wb') as pickle_file:
        pickle.dump(time_window_sec_stat, pickle_file)
    with open('../pickled_packet_parsed_in_time_window_sec', 'wb') as pickle_file:
        pickle.dump(packet_parsed_in_time_window_sec, pickle_file)
