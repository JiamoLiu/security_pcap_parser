
from utils import *
import networkx as nx
import matplotlib.pyplot as plt

#reload(utils)7
root_dir = "/path/to/dir/"

# Load from pickle
pkl_lst = unpickle_data("data.pkl")
packet_df_mapped = pkl_lst[0]
sessions_df_mapped = pkl_lst[1]
dev_mac_map = pkl_lst[2]
base_time = pkl_lst[3]

packet_df_mapped_ip = packet_df_mapped[packet_df_mapped["ip.dst"].notnull()].copy()
sessions_df_mapped_ip = sessions_df_mapped[sessions_df_mapped["ip.dst"].notnull()].copy()

print(sessions_df_mapped_ip.columns)