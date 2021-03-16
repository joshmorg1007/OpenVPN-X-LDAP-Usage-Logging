import re
import string
import os
import json
import sys
import platform
import time
from influxdb import InfluxDBClient

### File Paths
OPENVPNLOG_PATH = '/var/log/openvpn/status.log'### TEMP FILES PATHS
TMP_FILE_PATH = '/OpenVPNLogging/tmp/tmp.txt'
IP_LOOKUP_TABLE_PATH = '/OpenVPNLogging/IPLookup/IP_Table.json'
PREV_PULLED_DATA_PATH = 'prev_data.json'

###Regular Expressiosn
VPN_IP = re.compile(".*\d+,\d+")
VIRTUAL_IP = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},")
SUCCEED_AUTH = re.compile(".*succeeded for username")
NAME = re.compile ("\w+(?=')")
IP = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(?=:\d+)")

###influxdb Parameters
HOST = "192.168.71.108"
PORT = 8086

### Fucntions
def main():

    influx_client = InfluxDBClient(host=HOST, port=PORT)
    hostname = platform.uname()[1]
    database_name = hostname + "-VPN-Logging"
    influx_client.create_database(database_name)
    influx_client = InfluxDBClient(host=HOST, port=PORT, database=database_name)
    init_directories()

    concat_syslogs() #not needed for testing on windows machine

    if(os.path.exists(IP_LOOKUP_TABLE_PATH) == False):
        build_IP_lookup_table()

    user_data = get_and_match_user_data()

    ### Argument handling
    if len(sys.argv) < 2:
        print("Not Enough Arguments Provided")
        print("For list of arguments use python OpenVPNLogging.py help")
        return

    if sys.argv[1].casefold() == "help":
        help()
        return

    elif sys.argv[1].casefold() == "status":
        print_formated_data(user_data)
        purge_lookup_table()
        return

    elif sys.argv[1].casefold() == "log":
        prev_data = load_prev_pulled_data()
        if prev_data == False:
            for key in user_data.keys():
                current = user_data[key]
                log_login_event(influx_client, current)
                log_data_usage(influx_client, current[0], current[1], current[2], 0, 0)
                cache_prev(user_data)

        for key in user_data.keys():
            current = user_data[key]

            try:
                prev = prev_data[key]
            except:
                log_login_event(influx_client, current)
                log_data_usage(influx_client, current[0], current[1], current[2], 0, 0)
                cache_prev(user_data)
                continue

            data_up_delta = int(current[3]) - int(prev[3])
            do_login = False

            if(data_up_delta < 0):
                data_up_delta = 0
                do_login = True

            data_down_delta = int(current[4]) - int(prev[4])
            if(data_down_delta < 0):
                data_down_delta = 0
                do_login = True

            if(do_login == True):
                log_login_event(influx_client, current)

            log_data_usage(influx_client, current[0], current[1], current[2], data_up_delta, data_down_delta)

        cache_prev(user_data)
        purge_lookup_table()
        return


def build_IP_lookup_table():
    """Builds IP Lookup table JSON file through matching entries in status.log successful LDAP authentications in syslog """
    print("Building IP Lookup Table")
    if(os.path.exists(IP_LOOKUP_TABLE_PATH) == False):
        lookup = {}

    else:
        lookup = load_IP_lookup_table()

    ip_table = open(IP_LOOKUP_TABLE_PATH, "w")

    active = pull_active_IPs()
    auth = pull_successful_auth()

    for IP in active:

        try:
            lookup[IP] = auth[IP]
        except:
            print("No name matching: " + str(IP) + " in LDAP logs")
    json.dump(lookup, ip_table)

    ip_table.close()

def cache_prev(prev_data):
    prev_file = open(PREV_PULLED_DATA_PATH, "w")
    json.dump(prev_data, prev_file)

def load_IP_lookup_table():
    """loads IP Lookup JSON file to a python dictionary"""
    with open(IP_LOOKUP_TABLE_PATH, "r") as file:

        try:
            data = json.load(file)
        except:
            data = {}
        return data

def load_prev_pulled_data():
    """loads Prev Pulled Data file to a python dictionary"""
    with open(PREV_PULLED_DATA_PATH, "r") as file:

        try:
            data = json.load(file)
        except:
            return False
        return data

def purge_lookup_table():
    """Removes duplicate entries for users that have connected with different IPs"""
    ip_table = load_IP_lookup_table()
    reverse = []

    for entry in ip_table.values():
        if entry in reverse:
            os.remove(IP_LOOKUP_TABLE_PATH)
            build_IP_lookup_table()
        reverse.append(entry)

def get_and_match_user_data():
    """matches current info in status.log with IP Lookup table"""
    user_list_and_metrics = {}
    user_info, virt_IPs = pull_active_user_info()
    table = load_IP_lookup_table()

    for IP in user_info:
        try:
            if table[IP] is not None:
                name = table[IP]
                virt_ip = virt_IPs[IP]
                data_rec = user_info[IP][2]
                data_sent = user_info[IP][3]
                active_time = user_info[IP][4]

                metrics = [name, IP, virt_ip, data_rec, data_sent, active_time]

                user_list_and_metrics[IP] = metrics
        except:
            build_IP_lookup_table()
            table  = load_IP_lookup_table()

            try:
                name = table[IP]
                virt_ip = virt_IPs[IP]
                data_rec = user_info[IP][2]
                data_sent = user_info[IP][3]
                active_time = user_info[IP][4]

                metrics = [name, IP, virt_ip, data_rec, data_sent, active_time]

                user_list_and_metrics[IP] = metrics

            except:
                print("Issue with IP: " + IP)

    return user_list_and_metrics

def pull_active_user_info():
    """ Parses through status.log for current connection information"""
    with open(OPENVPNLOG_PATH, "r") as file:

        user_info = {}
        virt_IPs = {}
        for line in file.readlines():
            if VPN_IP.match(line) is not None:
                info = line.split(",")
                user_ip = info[1].split(":")[0]
                user_info[user_ip] = info

            elif VIRTUAL_IP.match(line) is not None:
                info = line.split(',')
                user_ip = info[2].split(":")[0]
                virt_IPs[user_ip] = info[0]

        return user_info, virt_IPs

def pull_active_IPs():
    """ Parses through status.log for active IPs"""
    IPs = []
    with open(OPENVPNLOG_PATH, "r") as file:
        for line in file.readlines():
            if VPN_IP.match(line) is not None:
                info = line.split(",")
                user_ip = info[1].split(":")[0]
                IPs.append(user_ip)
        return IPs

def pull_successful_auth():
    """ Parses through concatinated syslog for successful LDAP authentications"""
    with open(TMP_FILE_PATH, "r") as file:
        succeded = {}
        for line in file.readlines():
            if SUCCEED_AUTH.match(line) is not None:
                name = NAME.findall(line)
                ip = IP.findall(line)
                succeded[ip[0]] = name[0]
        return succeded

def log_login_event(influx_client, user_info):
    data_end_time = int(time.time() * 1000) #milliseconds
    print("logged in")
    log = list()

    log.append(
        {
                "measurement": "eventlog",
                "tags": {
                        "user": user_info[0], ###Change user to User
                        "IP": user_info[1],
                        "VirtIP": user_info[2]
                },
                "fields": {
                        "Event": "User Logged In"
                },
                "time": data_end_time
        }
        )

    client_write_start_time = time.perf_counter()
    influx_client.write_points(log, time_precision='ms', batch_size=10000, protocol='json')
    client_write_end_time = time.perf_counter()
    print("Client Library Write: {time}s".format(time=client_write_end_time - client_write_start_time))

def log_logout_event(influx_client, user_info): ### need to implement wen to call this function
    data_end_time = int(time.time() * 1000) #milliseconds
    print("logged in")
    log = list()

    log.append(
        {
                "measurement": "eventlog",
                "tags": {
                        "user": user_info[0],
                        "IP": user_info[1],
                        "VirtIP": user_info[2]
                },
                "fields": {
                        "Event": "User Logged out"
                },
                "time": data_end_time
        }
        )

    client_write_start_time = time.perf_counter()
    influx_client.write_points(log, time_precision='ms', batch_size=10000, protocol='json')
    client_write_end_time = time.perf_counter()
    print("Client Library Write: {time}s".format(time=client_write_end_time - client_write_start_time))

def log_data_usage(influx_client, name, IP, virt_IP, data_up, data_down):
    data_end_time = int(time.time() * 1000) #milliseconds
    print("logging data")
    log = list()

    log.append(
        {
                "measurement": "Download",
                "tags": {
                        "user": name,
                        "IP": IP,
                        "VirtIP": virt_IP
                },
                "fields": {
                        "data_down": data_down
                },
                "time": data_end_time
        }
        )

    log.append(
        {
                "measurement": "Upload",
                "tags": {
                        "user": name,
                        "IP": IP,
                        "VirtIP": virt_IP
                },
                "fields": {
                        "data_down": data_up ##need to change to "data_up" when implementing on real server
                },
                "time": data_end_time
        }
        )

    client_write_start_time = time.perf_counter()
    influx_client.write_points(log, time_precision='ms', batch_size=10000, protocol='json')
    client_write_end_time = time.perf_counter()
    print("Client Library Write: {time}s".format(time=client_write_end_time - client_write_start_time))

def print_formated_data(user_data):
    print("\n")
    print("################################################### CONNECTED USERS ###################################################")
    print ("{:<15} {:<18} {:<15} {:<25} {:<17} {:<25}".format('User Name','External IP','Virtual IP', 'Data Recieved From (MB)', 'Data Sent To (MB)', 'Connected Since: '))
    print("\n")
    for IP in user_data:
        name = user_data[IP][0]
        virt_ip = user_data[IP][2]
        data_rec = user_data[IP][3]
        data_sent = user_data[IP][4]
        active_time = user_data[IP][5]
        print ("{:<15} {:<18} {:<15} {:<25} {:<17} {:<25}".format(name, IP, virt_ip, float(data_rec)/1000000, float(data_sent)/1000000, active_time))

def concat_syslogs():
    """Concatinates all syslog files into one temp file"""
    os.system("/bin/cat /var/log/syslog.7.gz /var/log/syslog.6.gz /var/log/syslog.5.gz /var/log/syslog.4.gz /var/log/syslog.3.gz /var/log/syslog.2.gz | /bin/gunzip > " + TMP_FILE_PATH)
    os.system("/bin/cat /var/log/syslog.1 /var/log/syslog >> " + TMP_FILE_PATH)

def help():
    """print out command line arguments"""
    print("Not Implemented")

def init_directories():
    """Initialized the directories and files """
    try:
        os.mkdir('/OpenVPNLogging/')
    except:
        do = None
    try:
        os.mkdir('/OpenVPNLogging/tmp/')
    except:
        do = None
    try:
        os.mkdir('/OpenVPNLogging/IPLookup/')
    except:
        do = None
    try:
        file = open(IP_LOOKUP_TABLE_PATH, 'x')
        file.close()
    except:
        do = None
    try:
        file = open(TMP_FILE_PATH, 'x')
        file.close()
    except:
        do = None
    try:
        file = open(PREV_PULLED_DATA_PATH, 'x')
        file.close()
    except:
        do = None

if __name__ == "__main__":
    main()
