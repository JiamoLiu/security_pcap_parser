import json
import os
import pickle
import shutil
import pandas as pd
import tempfile
import subprocess
import random

from IPython.display import HTML, display

def update_map(d1, d2):
    d = {}
    for i in set(d1.keys() | d2.keys()):
        if d1.get(i) is None:
            d[i] = d2.get(i)
        elif d2.get(i) is None:
            d[i] = d1.get(i)
        else:
            d[i] = set([d1.get(i)] + [d2.get(i)])
    return d

def map_to_host(input_df, data_dir, json_file_name="hosts.json", post_process_dir="post_process", csv_sub_dir="split-sess"):
    df_ext = input_df.loc[(input_df["is_external_pcap"])].copy()
    df_local = input_df.loc[~(input_df["is_external_pcap"])].copy()

    if not df_ext.empty:
        df_ext_mod, dev_mac_map_ext = map_to_host_external(df_ext)
    df_loc_mod, dev_mac_map_loc = map_to_host_local(df_local, data_dir, json_file_name, post_process_dir,
                                                       csv_sub_dir)

    if not df_ext.empty:
        out_df = pd.concat([df_ext_mod, df_loc_mod], ignore_index=True, sort=False)
        dev_mac_map = update_map(dev_mac_map_ext, dev_mac_map_loc)
    else:
        out_df = df_loc_mod
        dev_mac_map = dev_mac_map_loc

    return out_df, dev_mac_map


def map_to_host_local(input_df, data_dir, json_file_name, post_process_dir, csv_sub_dir):
    json_file_path = os.path.join(data_dir, json_file_name)
    input_df["host_src"] = input_df["eth.src"]
    input_df["host_dst"] = input_df["eth.dst"]
    with open(json_file_path) as json_file:
        jmap = json.load(json_file)
        if type(list(jmap.values())[0]) is not dict:
            dev_mac_map = jmap
            mac_dev_map = {v: k for k, v in jmap.items()}
        else:
            split_sess_folder = os.path.join(data_dir, post_process_dir, csv_sub_dir)
            mac_map_file_path = os.path.join(split_sess_folder, "mac_map.json")
            if not os.path.exists(mac_map_file_path):
                print("Error!! MAC-to-MAC map file is missing! Aborting...")
                return
            with open(mac_map_file_path, "r") as jfile:
                mac_map = json.load(jfile)

            outer_mac_dev_map = {v['mac']: k for k, v in jmap.items()}
            #print(dev_mac_map)
            mac_dev_map = {}
            for k in mac_map:
                mac_dev_map[k] = outer_mac_dev_map[mac_map[k][0]]
            mac_dev_map['ff:ff:ff:ff:ff:ff'] = 'DOCKER_BROADCAST'
            dev_mac_map = {v: k for k, v in mac_dev_map.items()}
            #print(dev_mac_map)

        input_df.replace({"host_src": mac_dev_map}, inplace=True)
        input_df.replace({"host_dst": mac_dev_map}, inplace=True)


    #print("dev_mac_map:" + str(dev_mac_map))
    #print("mac_dev_map:" + str(mac_dev_map))
    #print(input_df.head())


    return input_df, dev_mac_map

copy_from_capture_host_banner = "BANNER-TO-USE-IN-PLACE-TO-COPY-FROM-CAPTURE-HOST"
def map_to_host_external(input_df):
    #Based on external or internal do something different
    if not input_df.empty:
        #input_df["host_src"] = input_df["eth.src"]
        #input_df["host_dst"] = input_df["eth.dst"]

        input_df_with_ip = input_df.loc[input_df["ip.dst"].notnull()].copy()
        input_df_wo_ip = input_df.loc[input_df["ip.dst"].isnull()].copy()


        ip_host_map1 = dict(zip(input_df_with_ip['ip.src'], input_df_with_ip['capture_hostname']))
        ip_host_map2 = dict(zip(input_df_with_ip['ip.dst'], input_df_with_ip['capture_hostname']))
        ip_host_map = {**ip_host_map1, **ip_host_map2}
        ip_host_map_final = {ip: 'GLOBAL_INTERNET' for ip in ip_host_map}

        # Populate portion without IP
        input_df_wo_ip["host_src"] = input_df_wo_ip["eth.src"]
        input_df_wo_ip["host_dst"] = input_df_wo_ip["eth.dst"]
        ip_eth_map1 = dict(zip(input_df_with_ip['eth.src'], input_df_with_ip['ip.src']))
        ip_eth_map2 = dict(zip(input_df_with_ip['eth.dst'], input_df_with_ip['ip.dst']))
        ip_eth_map = {**ip_eth_map1, **ip_eth_map2}

        all_macs = input_df['eth.src'].unique().tolist() + input_df['eth.dst'].unique().tolist()
        mac_host_map = {mac: 'GLOBAL_INTERNET' for mac in all_macs}
        for mac in all_macs:
            if mac == 'ff:ff:ff:ff:ff:ff':
                mac_host_map[mac] = 'DOCKER_BROADCAST'
            elif mac in ip_eth_map:
                mac_host_map[mac] = ip_host_map_final[ip_eth_map[mac]]

        # Remove the _external suffix
        #for mac in mac_host_map:
        #    mac_host_map[mac] = mac_host_map[mac].replace("_external", "")

        input_df_wo_ip.replace({"host_src": mac_host_map}, inplace=True)
        input_df_wo_ip.replace({"host_dst": mac_host_map}, inplace=True)

        # Populate portion with IP
        input_df_with_ip["host_src"] = input_df_with_ip['ip.src']
        input_df_with_ip["host_dst"] = input_df_with_ip['ip.dst']


        for ip in ip_host_map:
            if ip == '10.1.1.1' or ip.startswith('172.18.'):
                ip_host_map_final[ip] = copy_from_capture_host_banner
        input_df_with_ip.replace({"host_src": ip_host_map_final}, inplace=True)
        input_df_with_ip.replace({"host_dst": ip_host_map_final}, inplace=True)
        input_df_with_ip.loc[input_df_with_ip["host_src"] == copy_from_capture_host_banner, "host_src"] = \
            input_df_with_ip["capture_hostname"]
        input_df_with_ip.loc[input_df_with_ip["host_dst"] == copy_from_capture_host_banner, "host_dst"] = \
            input_df_with_ip["capture_hostname"]



        dev_mac_map = {mac_host_map[k]: k for k in mac_host_map.keys()}
        out_df = pd.concat([input_df_with_ip, input_df_wo_ip], ignore_index=True, sort=False)

        out_df["host_src"] = out_df["host_src"].str.replace("_external", "")
        out_df["host_dst"] = out_df["host_dst"].str.replace("_external", "")

        return out_df, dev_mac_map


def gen_host_tuples(dev_mac_map):
    hosts = list(dev_mac_map.keys())
    host_tuples = []
    for i, host1 in enumerate(hosts):
        for j, host2 in enumerate(hosts):
            if j != i:
                host_tuples.extend([(host1, host2)])
    return host_tuples


def gen_all_metric_by_hosts(df, dev_mac_map, metric_func, has_ip=True):
    metric_list = []
    host_tuples = gen_host_tuples(dev_mac_map)
    for host_tuple in host_tuples:
        host1 = host_tuple[0]
        host2 = host_tuple[1]
        metric_list.append([host1, host2, metric_func(df, host1, host2, has_ip)])
    return metric_list


def packets_rcvd_by_hosts(df, capture_host, src_host, has_ip=True):
    if has_ip:
        return df.loc[(df["capture_hostname"] == capture_host) & (df["host_src"] == src_host)
                      & (df["ip.src"].notnull()) & (df["ip.dst"].notnull())]
    else:
        return df.loc[(df["capture_hostname"] == capture_host) & (df["host_src"] == src_host)]


def packets_sent_by_hosts(df, capture_host, dst_host, has_ip=True):
    if has_ip:
        return df.loc[(df["capture_hostname"] == capture_host) & (df["host_dst"] == dst_host)
                      & (df["ip.src"].notnull()) & (df["ip.dst"].notnull())]
    else:
        return df.loc[(df["capture_hostname"] == capture_host) & (df["host_dst"] == dst_host)]


def sessions_rcvd_by_hosts(df, capture_host, src_host, has_ip=True):
    if has_ip:
        return df.loc[(df["capture_hostname"] == capture_host) & (df["host_src"] == src_host)
                      & (df["ip.src"].notnull()) & (df["ip.dst"].notnull())]
    else:
        return df.loc[(df["capture_hostname"] == capture_host) & (df["host_src"] == src_host)]


def sessions_sent_by_hosts(df, capture_host, dst_host, has_ip=True):
    if has_ip:
        return df.loc[(df["capture_hostname"] == capture_host) & (df["host_dst"] == dst_host)
                      & (df["ip.src"].notnull()) & (df["ip.dst"].notnull())]
    else:
        return df.loc[(df["capture_hostname"] == capture_host) & (df["host_dst"] == dst_host)]


def count_sessions_rcvd_by_hosts(df, capture_host, src_host, has_ip=True):
    return len(sessions_rcvd_by_hosts(df, capture_host, src_host, has_ip))


def count_sessions_sent_by_hosts(df, capture_host, dst_host, has_ip=True):
    return len(sessions_sent_by_hosts(df, capture_host, dst_host, has_ip))


def count_packets_sent_by_hosts(df, host1, host2, has_ip=True):
    return len(packets_sent_by_hosts(df, host1, host2, has_ip))


def count_total_packet_size_sent_by_hosts(df, host1, host2, has_ip=True):
    return packets_sent_by_hosts(df, host1, host2, has_ip)['frame.cap_len'].sum()


def count_packets_by_hosts(df, host1, host2, has_ip=True):
    return len(packets_rcvd_by_hosts(df, host1, host2, has_ip))


def count_total_packet_size_rcvd_by_hosts(df, host1, host2, has_ip=True):
    return packets_rcvd_by_hosts(df, host1, host2, has_ip)['frame.cap_len'].sum()


'''
def count_session_by_hosts(df, host1, host2, has_ip=True):
    df_packets = packets_by_hosts(df, host1, host2, has_ip)
    return len(df_packets['split_id'].unique())
'''


# Returns a copy of the df in a specific relative window
def df_time_window(df, base_time, time_window):
    #base_time = df['frame.time_epoch'].min()

    return df.loc[(df['frame.time_epoch'] >= base_time + time_window[0]) &
        (df['frame.time_epoch'] < base_time + time_window[1])]


def pickle_data(mylist, pkl_path):
    with open(pkl_path, 'wb') as f:
        pickle.dump(mylist, f)


def unpickle_data(pkl_path):
    if not os.path.exists(pkl_path):
        print(f"The file '{pkl_path}' does not exists!! Skipping!!")
        return None
    with open(pkl_path, 'rb') as f:
        mynewlist = pickle.load(f)
    return mynewlist


def map_set_to_json(m):
    return dict([(i, list(m[i])) for i in set(m.keys())])


def create_df_func_time_window(df, dev_mac_map, base_time, func, interval, max_rep):
    metric_list = []
    for i in range(max_rep):
        df_tmp = df_time_window(df, base_time, [i * interval, (i + 1) * interval - 1])
        metric_list.append(gen_all_metric_by_hosts(df_tmp, dev_mac_map, func))
    return metric_list


def create_animation(metric_list, dev_mac_map, duration=1, reverse_e_order=False):
    temp_dir = tempfile.TemporaryDirectory()
    dir_name = temp_dir.name

    #dir_name = "/tmp/images/"

    v = Visualization(list(dev_mac_map))
    with open(os.path.join(dir_name, "ffmpeg_input.txt"), 'w') as my_file:
        for i, metric in enumerate(metric_list):
            v.add_edges(metric)
            v.draw_graph(i, save_graph=True, save_path=os.path.join(dir_name, str(i) + ".png"), reverse_edge_order=reverse_e_order)
            for i in range(10):
                img_file_name = os.path.join(dir_name, str(i) + ".png")
                my_file.write("file '" + img_file_name + "'\n")
                my_file.write("duration " + str(duration) + "\n")

    #print(temp_dir.name)

    video_file_name = os.path.join(dir_name, 'video.gif')
    command = [
        'ffmpeg', '-y','-safe', '0', '-f', 'concat', '-i', os.path.join(dir_name, "ffmpeg_input.txt"),
        '-framerate', '0.02', '-r', '30', '-pix_fmt', 'yuv420p',
        video_file_name
    ]

    subprocess.call(command)
    cdir = os.path.dirname(os.path.realpath(__file__))
    shutil.copyfile(video_file_name, os.path.join(cdir, 'video.gif'))


def show_animation():
    # borrowed from https://stackoverflow.com/questions/37023166/how-to-reload-image-in-ipython-notebook

    __counter__ = random.randint(0, 2e9)

    display(HTML('<img src="video.gif?" ' + str(__counter__) +
                 'height="100">'))
