import dpkt, os
import io
import random

from dpkt.ethernet import ETH_TYPE_IP
from dpkt.ip import IP_PROTO_TCP, IP_PROTO_UDP


"""
Src_file_name = 'D:\\tasks\\Projects\\KISA IoT 2년차 (2019년 1월 ~)\\' \
                '네트워크패킷수집\\ezviz_traffic_sample\\190711_2_NUGU_Scanning_HOST+PORT_total-dec.pcap'
"""

Src_file_name = 'D:\\VM\\shared\\00_frag.pcapng'
Base_file_name = 'D:\\VM\\shared\\00_frag_udp.pcapng'
Exported_file_name = 'D:\\VM\\shared\\modified.pcapng'

"""
Base_file_name = 'D:\\tasks\\Projects\\KISA IoT 2년차 (2019년 1월 ~)\\' \
                '네트워크패킷수집\\ezviz_traffic_sample\\190711_2_NUGU_Scanning_HOST+PORT_total-dec.pcap'
Exported_file_name = 'D:\\tasks\Projects\\KISA IoT 2년차 (2019년 1월 ~)\\' \
                     '네트워크패킷수집\\ezviz_traffic_sample\\modified_file.pcap'
"""
Field_conversion_table = {'src_ip': {'192.168.61.1': '111.222.0.4'},
                          'dst_ip': {},
                          'src_mac': {'00:50:56:c0:00:08': '11:22:33:44:55:66'},
                          'dst_mac': {}}


def _convert_addr_str_to_byte(addr_str, protocol='IPv4'):
    if protocol == 'IPv4' and type(addr_str) is str and addr_str.count('.') == 3:
        splitted_addr_int = addr_str.split('.')
        converted_addr = bytes([int(x) for x in splitted_addr_int])

        return converted_addr
    elif protocol == 'IPv6':
        raise NotImplementedError
    else:
        raise Exception('@ Error\n\tInvalid parameter - convert_addr_str_to_byte()')


def _convert_addr_byte_to_str(addr_bytes, protocol='IPv4'):
    converted_addr = ''

    if protocol == 'IPv4' and type(addr_bytes) is bytes and len(addr_bytes) == 4:
        for addr_idx in range(4):
            temp_str = ".%d" % addr_bytes[addr_idx]
            converted_addr += temp_str
        return converted_addr[1:]
    elif protocol == 'IPv6' and type(addr_bytes) is bytes and len(addr_bytes) == 16:
        for addr_idx in range(16):
            temp_str = ''
            if addr_idx % 2 == 0:
                temp_str += ':'
            temp_str += "%02x" % (addr_bytes[addr_idx])
            converted_addr += temp_str
        return converted_addr[1:]
    else:
        raise Exception('@ Error\n\tInvalid parameter - convert_addr_byte_to_str()')


def _convert_mac_addr_byte_to_str(mac_addr_bytes, mac_addr_length=6):
    converted_addr = ''

    if type(mac_addr_bytes) is bytes and len(mac_addr_bytes) == mac_addr_length:
        for addr_idx in range(mac_addr_length):
            temp_str = ":%02x" % mac_addr_bytes[addr_idx]
            converted_addr += temp_str
    else:
        raise Exception('@ Error\n\tInvalid parameter - convert_mac_addr_byte_to_str()')

    return converted_addr[1:]


def _convert_mac_addr_str_to_byte(mac_addr_str):
    if type(mac_addr_str) is str and mac_addr_str.count(':') == 5:
        splitted_mac_addr_int = mac_addr_str.split(':')
        converted_mac_addr = bytes([int(x, 16) for x in splitted_mac_addr_int])

        return converted_mac_addr
    else:
        raise Exception('@ Error\n\tInvalid parameter - convert_mac_addr_str_to_byte()')


def _close_file(file_handle):
    if isinstance(file_handle, io.IOBase):
        file_handle.close()
    else:
        print('Warning - The parameter is not a file object.')
        return -1


def _is_ip_protocol(ether_level):
    eth_type = ether_level.type

    if eth_type == ETH_TYPE_IP:
        ip_level = ether_level.data
        if ip_level.p in [IP_PROTO_TCP, IP_PROTO_UDP]:
            return True
        else:
            return False
    else:
        return False


def load_and_read_pcap(file_name):
    src_file = open(file_name, 'rb')

    if Src_file_name.find('.pcapng') >= 0:
        read_instance = dpkt.pcapng.Reader(src_file)
    elif Src_file_name.find('.pcap') >= 0:
        read_instance = dpkt.pcap.Reader(src_file)
    else:
        raise NotImplementedError

    return src_file, read_instance


def modify_packets(new_base_timestamp):
    src_file_handle, src_ts_pkt = load_and_read_pcap(Src_file_name)

    timestamp_diff = None
    modified_ts_pkt = list()

    for ts, pkt in src_ts_pkt:
        if timestamp_diff is None:
            timestamp_diff = new_base_timestamp - ts

        ether_level = dpkt.ethernet.Ethernet(pkt)
        ip_level = ether_level.data

        original_src_mac = _convert_mac_addr_byte_to_str(ether_level.src)
        print(original_src_mac)
        if original_src_mac in Field_conversion_table['src_mac']:
            new_src_mac = _convert_mac_addr_str_to_byte(Field_conversion_table['src_mac'][original_src_mac])
            ether_level.src = new_src_mac

        original_dst_mac = _convert_mac_addr_byte_to_str(ether_level.dst)
        if original_dst_mac in Field_conversion_table['dst_mac']:
            new_dst_mac = _convert_mac_addr_str_to_byte(Field_conversion_table['dst_mac'][original_dst_mac])
            ether_level.dst = new_dst_mac

        if _is_ip_protocol(ether_level) is True:
            original_src_ip = _convert_addr_byte_to_str(ip_level.src, 'IPv4')
            if original_src_ip in Field_conversion_table['src_ip']:
                new_src_ip = _convert_addr_str_to_byte(Field_conversion_table['src_ip'][original_src_ip])
                ip_level.src = new_src_ip

            original_dst_ip = _convert_addr_byte_to_str(ip_level.dst, 'IPv4')
            if original_dst_ip in Field_conversion_table['dst_ip']:
                new_dst_ip = _convert_addr_str_to_byte(Field_conversion_table['dst_ip'][original_dst_ip])
                ip_level.dst = new_dst_ip

        modified_pkt = bytes(ether_level)
        new_ts = ts + timestamp_diff

        modified_ts_pkt.append((new_ts, modified_pkt))

    _close_file(src_file_handle)

    return modified_ts_pkt


def export_packets(ts_pkt):
    with open(Exported_file_name, 'wb') as exported_file:
        pcap_writer = dpkt.pcap.Writer(exported_file)

        for ts, pkt in ts_pkt:
            pcap_writer.writepkt(pkt, ts)

        print('Export completed - ' + os.path.basename(Exported_file_name))


def merge_base_packet(target_ts_pkt):
    base_file_handle, base_ts_pkt = load_and_read_pcap(Base_file_name)

    merged_ts_pkt = list(target_ts_pkt) + list(base_ts_pkt)
    merged_ts_pkt.sort(key=lambda x: x[0])

    _close_file(base_file_handle)
    return merged_ts_pkt


def get_random_base_timestamp(src_ts_start, src_ts_end, base_ts_start, base_ts_end):
    valid_ts_start = base_ts_start
    valid_ts_end = base_ts_end - (src_ts_end - src_ts_start)

    new_random_base_timestamp = (valid_ts_end - valid_ts_start) * random.random() + valid_ts_start

    return new_random_base_timestamp


def get_timestamp_range(file_name):
    file_handle, ts_pkt = load_and_read_pcap(file_name)

    timestamp_start = None
    timestamp_end = None

    for ts, _ in ts_pkt:
        if timestamp_start is None:
            timestamp_start = ts
        timestamp_end = ts

    _close_file(file_handle)

    return timestamp_start, timestamp_end


def run():
    src_ts_start, src_ts_end = get_timestamp_range(Src_file_name)
    base_ts_start, base_ts_end = get_timestamp_range(Base_file_name)

    new_base_timestamp = get_random_base_timestamp(src_ts_start, src_ts_end, base_ts_start, base_ts_end)

    modified_ts_pkt = modify_packets(new_base_timestamp)
    merged_ts_pkt = merge_base_packet(modified_ts_pkt)
    export_packets(merged_ts_pkt)


if __name__ == "__main__":
    run()
