import pandas as pd
import re
def expand_port_range(port_range):

    if '-' in port_range:
        start, end = port_range.split('-')
        return range(int(start), int(end) + 1)
    elif '–' in port_range:
        start, end = port_range.split('–')
        return range(int(start), int(end) + 1)
    else:
        return [int(port_range)]

# Apply the function and explode




url = 'https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers'
tables = pd.read_html(url)
#print(tables)
well_known_ports = tables[4]
well_known_ports["type"] = "well_known"
registered_ports = tables[5]
registered_ports["type"] = "registered"



all_ports = pd.concat([well_known_ports,registered_ports])

def remove_pattern(text):
    return re.sub(r"\[.*?\]", "", text)

# Apply the function to the 'port' column
all_ports['Port'] = all_ports['Port'].apply(remove_pattern)



all_ports['Port'] = all_ports['Port'].apply(expand_port_range)
all_ports = all_ports.explode('Port')
all_ports = all_ports.drop_duplicates(subset='Port', keep='first')
all_ports.to_csv("ports_mapping.csv",index=False)