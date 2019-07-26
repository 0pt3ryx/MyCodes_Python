import dpkt, os
import datetime, time


Src_file_name = 'D:\\tasks\\Projects\\KISA IoT 2년차 (2019년 1월 ~)\\' \
                '네트워크패킷수집\\ezviz_traffic_sample\\190711_2_NUGU_Scanning_HOST+PORT_total-dec.pcap'
Exported_file_name = 'D:\\tasks\Projects\\KISA IoT 2년차 (2019년 1월 ~)\\' \
                     '네트워크패킷수집\\ezviz_traffic_sample\\modified_file.pcap'

Base_packet_datetime = '2019-07-11 15:00:00'
Field_conversion_table = {'src_ip': {'218.38.139.37': '111.111.000.111'},
                          'dst_ip': {},
                          'src_mac': {},
                          'dst_mac': {}}


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


def load_and_read_pcap(file_name):
    src_file = open(file_name, 'rb')

    if Src_file_name.find('.pcapng') >= 0:
        read_instance = dpkt.pcapng.Reader(src_file)
    elif Src_file_name.find('.pcap') >= 0:
        read_instance = dpkt.pcap.Reader(src_file)
    else:
        raise NotImplementedError

    return read_instance


def modify_packets(pcap_instance):
    datetime_obj = datetime.datetime.strptime(Base_packet_datetime, '%Y-%m-%d %H:%M:%S')
    base_timestamp = time.mktime(datetime_obj.timetuple())

    timestamp_diff = None
    modified_ts_pkt = list()

    for ts, pkt in pcap_instance:
        if timestamp_diff is None:
            timestamp_diff = base_timestamp - ts

        # print(datetime.datetime.fromtimestamp(ts))
        # print(base_timestamp-ts)

        new_ts = ts + timestamp_diff
        modified_ts_pkt.append((new_ts, pkt))

    return modified_ts_pkt


def export_modified_packets(modified_ts_pkt):
    with open(Exported_file_name, 'wb') as exported_file:
        pcap_writer = dpkt.pcap.Writer(exported_file)

        for ts, pkt in modified_ts_pkt:
            pcap_writer.writepkt(pkt, ts)

        print('Export completed - ' + os.path.basename(Exported_file_name))


def run():
    read_pcap_instance = load_and_read_pcap(Src_file_name)
    modified_ts_pkt = modify_packets(read_pcap_instance)
    export_modified_packets(modified_ts_pkt)


if __name__ == "__main__":
    run()
