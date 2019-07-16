import csv
import copy

Src_file_path = 'D:\\tasks\\Projects\\KISA IoT 2년차 (2019년 1월 ~)' \
                '\\네트워크패킷수집\\ezviz_traffic_sample\\extracted_features\\190711_3_ezviz_Scanning_HOST+PORT_total-dec.csv'
Dst_file_path = 'D:\\tasks\\Projects\\KISA IoT 2년차 (2019년 1월 ~)' \
                '\\네트워크패킷수집\\ezviz_traffic_sample\\extracted_features\\190711_3_ezviz_Scanning_HOST+PORT_feature.csv'


# Modify this function to label
def _get_label(field_dict):
    eth_src = field_dict['src_ether']
    eth_dst = field_dict['dst_ether']
    protocol = field_dict['protocol_type']
    frame_number = int(field_dict['idx'])
    tcp_window_size = int(field_dict['tcp_win_size'])

    ip_src = field_dict['src_ip']
    ip_dst = field_dict['dst_ip']

    flag = field_dict['flag']
    tcp_flags_syn = False
    tcp_flags_reset = False
    if 'SYN' in flag:
        tcp_flags_syn = True
    if 'RST' in flag:
        tcp_flags_reset = True

    if eth_src == 'f0:18:98:5e:ff:9f' and protocol == 'ARP' and eth_dst == 'ff:ff:ff:ff:ff:ff' and frame_number < 2000:
        return 'host_discover'
    elif ip_src == '192.168.0.15' and ip_dst == '192.168.0.13' and ((tcp_flags_syn and tcp_window_size == 1024) or tcp_flags_reset):
        return 'port_scan'
    else:
        return 'normal'


def _load_src_file(src_file_path):
    result_list = list()

    with open(src_file_path, 'r') as src_file:
        reader = csv.DictReader(src_file)
        for line in reader:
            label = _get_label(line)
            new_row = copy.deepcopy(line)
            new_row['label'] = label
            result_list.append(new_row)

    return result_list


def _save_into_dst_file(dst_file_path, result_list):
    field_names = result_list[0].keys()

    with open(dst_file_path, 'w', newline='\n') as dst_file:
        writer = csv.DictWriter(dst_file, fieldnames=field_names)
        writer.writeheader()
        writer.writerows(result_list)


def run():
    result_list = _load_src_file(Src_file_path)
    _save_into_dst_file(Dst_file_path, result_list)


run()
