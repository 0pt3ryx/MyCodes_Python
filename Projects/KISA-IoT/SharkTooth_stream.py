import socket
import sys
import os
import queue
from threading import Thread
import SharkTooth

HOST = '127.0.0.1'
PORT = 9000
SAVE_DIR = 'Savefolder\\'
try:
    os.makedirs(SAVE_DIR)
except FileExistsError:
    pass
SAVE_FILENAME = 'save_%i.pcap'
Received_file_queue = queue.Queue()

EXPORT_DIR = 'extracted_features\\'
try:
    os.makedirs(EXPORT_DIR)
except FileExistsError:
    pass
EXPORT_FILENAME = 'extracted_feature_%i.csv'


def _socket_communication_thread_func(client_socket):
    client_socket.settimeout(30.0)
    file_index = 0

    try:
        while True:
            save_filename = SAVE_DIR + SAVE_FILENAME % file_index
            with open(save_filename, 'wb') as file:
                while True:
                    data = client_socket.recv(4096)
                    if data.endswith(b'end'):
                        file.write(data[:data.find(b'end')])
                        print('Writing {0} done'.format(save_filename))
                        break
                    file.write(data)
            print(save_filename)
            Received_file_queue.put(save_filename)

            reply = save_filename + ' received'
            print(reply)
            client_socket.send(reply.encode())
            file_index += 1
    except socket.timeout:
        print('Done receiving.', end=' ')
        client_socket.close()
        print('Client socket is closed')


def _feature_extraction_thread_func():
    global Received_file_queue
    file_index = 0

    while True:
        if Received_file_queue.qsize() <= 0:
            continue
        src_pcap_file_rel_path = Received_file_queue.get()
        dst_csv_file_rel_path = EXPORT_DIR + EXPORT_FILENAME % file_index

        SharkTooth.extract_feature(src_pcap_file_rel_path, dst_csv_file_rel_path)

        file_index += 1


if __name__ == "__main__":
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('Failed to create client socket')
        sys.exit()
    print('Client socket Created')

    try:
        client.connect((HOST, PORT))
    except socket.gaierror:
        print('Hostname could not be resolved. Exiting...')
        sys.exit()
    print('Client socket connected to server on ip {0}'.format(HOST))

    sock_comm_thread = Thread(target=_socket_communication_thread_func, args=(client, ))
    feature_ex_thread = Thread(target=_feature_extraction_thread_func, args=())

    sock_comm_thread.start()
    feature_ex_thread.start()

    sock_comm_thread.join()
    feature_ex_thread.join()
