import re
import string
import os
import json
import sys
import platform
import time
from datetime import datetime, timedelta, timezone
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from influxdb_client import BucketsService, Bucket, PostBucketRequest, BucketRetentionRules
from crontab import CronTab


###Regular Expressiosn
VPN_IP = re.compile(".*\d+,\d+")
VIRTUAL_IP = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},")
SUCCEED_AUTH = re.compile(".*succeeded for username")
FAILED_AUTH = re.compile(".*TLS Auth Error")
NAME = re.compile ("\w+(?=')")
IP = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(?=:\d+)")
DATE = re.compile("\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}")


### Fucntions
def main():

    ### Loading From Config
    try:
        installed_path = os.path.dirname(os.path.realpath(__file__))
        with open(installed_path + '/config.json', "r") as file:
            data = json.load(file)
        ORG = data["org"]
        ORG_ID = data["org_id"]
        TOKEN = data["token"]
        URL = data["url"]
        TMP_FILE_PATH = data["tmp_path"]
        IP_LOOKUP_TABLE_PATH = data["ip_path"]
        PREV_PULLED_DATA_PATH = data["cache_path"]
        SYS_LOG_PATH = data["syslog"]
        OPENVPNLOG_PATH = data["vpn_status"]
        BUCKET = platform.uname()[1] + "-VPN"
    except:
        print("Issue with Config")
        init_environment()

    ###influxdb Parameters
    start_time = time.perf_counter()
    client = InfluxDBClient(url= URL, token= TOKEN, org= ORG)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    bucket_api = client.buckets_api()

    try:
        bucket_api.create_bucket(bucket= Bucket(name =BUCKET, org_id=ORG_ID, retention_rules=[BucketRetentionRules(every_seconds=604800)] ))
    except:
        print("Bucket already exits")
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

    elif sys.argv[1].casefold() == "init":
        init_environment()
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
                log_login_event(client, current)
                log_data_usage(client, current[0], current[1], current[2], 0, 0)
                cache_prev(user_data)

        log_active_users(client, user_data)
        log_failed_auth(client)

        for key in prev_data.keys():
            prev = prev_data[key]

            try:
                current = user_data[key]
            except: ### indicates user no longer in the current users list, meaning logout event
                log_logout_event(client, prev)
                log_data_usage(client, prev[0], prev[1], prev[2], 0, 0) ### adds entry with 0s for both upload and data afer logout event in order to make the last() function in influx return useful results

        for key in user_data.keys():
            current = user_data[key]

            try:
                prev = prev_data[key]
            except:### indicates user is not listed in prev_data cache therefore login event occured
                log_login_event(client, current)
                log_data_usage(client, current[0], current[1], current[2], 0, 0) ### Inisializes user records with zeroes
                cache_prev(user_data)
                continue

            do_login = False
            data_up_delta = int(current[3]) - int(prev[3])

            if(data_up_delta < 0):### Fix to the issue when user would disconnect then connect within the 1 minute window of the script being called, resulting in a negative delta
                data_up_delta = 0
                do_login = True

            data_down_delta = int(current[4]) - int(prev[4])

            if(data_down_delta < 0):### Fix to the issue when user would disconnect then connect within the 1 minute window of the script being called, resulting in a negative delta
                data_down_delta = 0
                do_login = True

            if(do_login == True):### Fix to the issue when user would disconnect then connect within the 1 minute window of the script being called, resulting in a negative delta
                log_logout_event(client, current)
                log_login_event(client, current)


            if(datetime_to_mili_two(current[5]) < datetime_to_mili_two(prev[5])): ### Fix to the issue where the OpenVPN log's track of the data would reset, then revert back after a period of time
                cache_prev(user_data)
                data_down_delta = 0
                data_up_delta = 0

            log_data_usage(client, current[0], current[1], current[2], data_up_delta, data_down_delta)

        cache_prev(user_data)
        purge_lookup_table()
        end_time = time.perf_counter()
        print("Total Runtime: {time}s".format(time=end_time - start_time))
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
    """writes the previous data to a json file acting as a cache to be used to calculate the delta of data used"""
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

def log_failed_auth(client):
    """Parses through syslog file to find Authentication Failure events and adds a log into the eventlog measurement"""
    with open(SYS_LOG_PATH, 'r') as file:#need to change to syslog after done testing
        log = list()
        for line in file.readlines():
            if FAILED_AUTH.match(line) is not None:
                ip = IP.findall(line)
                date_time = DATE.findall(line)

                date_time = get_con_datetime(date_time[0])
                date_time = date_time.replace(tzinfo=timezone.utc).astimezone(tz=None)
                date_time = date_time.isoformat("T")
                date_time = date_time[:19] + 'z'

                log.append(Point("eventlog").tag("User", "Unknown").tag("IP", ip[0]).field("Event", "User Failed Authentication").time(date_time))


    client_write_start_time = time.perf_counter()
    write_api.write(bucket=BUCKET, org = ORG, record=log)
    client_write_end_time = time.perf_counter()
    print("Client Library Write: {time}s".format(time=client_write_end_time - client_write_start_time))

def log_login_event(client, user_info):
    """Adds a Login Event to the eventlog measurement"""
    data_end_time = int(time.time() * 1000) #milliseconds
    now = datetime.utcnow()
    now = now.isoformat("T") + "Z"
    log = list()

    log.append(Point("eventlog").tag("User", user_info[0]).tag("IP", user_info[1]).tag("VirtIP", user_info[2]).field("Event", "User Logged In").time(now))


    client_write_start_time = time.perf_counter()
    write_api.write(bucket=BUCKET, org = ORG, record=log)
    client_write_end_time = time.perf_counter()
    print("Client Library Write: {time}s".format(time=client_write_end_time - client_write_start_time))

def log_logout_event(client, user_info):
    """Adds a Logout Event to the eventlog measurement"""
    data_end_time = int(time.time() * 1000) #milliseconds

    now = datetime.utcnow()
    now = now.isoformat("T") + "Z"

    log = list()

    log.append(Point("eventlog").tag("User", user_info[0]).tag("IP", user_info[1]).tag("VirtIP", user_info[2]).field("Event", "User Logged Out").time(now))

    client_write_start_time = time.perf_counter()
    write_api.write(bucket=BUCKET, org = ORG, record=log)
    client_write_end_time = time.perf_counter()
    print("Client Library Write: {time}s".format(time=client_write_end_time - client_write_start_time))

def log_active_users(client, user_data):
    """Drops the old statuslog measurement then adds all currently connected users to the satuslog measurement"""

    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)

    now = now.isoformat("T") + "Z"
    hour_ago = hour_ago.isoformat("T") + "Z"
    client.delete_api().delete(hour_ago, now, '"_measurement"="statuslog"', bucket = BUCKET, org=ORG)

    log = list()
    for key in user_data.keys():
        current = user_data[key]
        data_end_time = int(time.time() * 1000) #milliseconds

        log.append(Point("statuslog").tag("User", current[0]).tag("IP", current[1]).tag("VirtIP", current[2]).field("Event", "User Active").time(now))

    client_write_start_time = time.perf_counter()
    write_api.write(bucket=BUCKET, org = ORG, record=log)
    client_write_end_time = time.perf_counter()
    print("Client Library Write: {time}s".format(time=client_write_end_time - client_write_start_time))

def log_data_usage(client, name, IP, virt_IP, data_up, data_down):
    """adds a Download and Upload usage measurement to the database for each user connected"""
    data_end_time = int(time.time() * 1000) #milliseconds
    now = datetime.utcnow()
    now = now.isoformat("T") + "Z"
    print("logging data")
    log = list()

    log.append(Point("Download").tag("User", name).tag("IP", IP).tag("VirtIP", virt_IP).field("data_down", data_down).time(now))
    print(data_down)

    log.append(Point("Upload").tag("User", name).tag("IP", IP).tag("VirtIP", virt_IP).field("data_up", data_up).time(now))

    client_write_start_time = time.perf_counter()
    write_api.write(bucket=BUCKET, org = ORG, record=log)
    client_write_end_time = time.perf_counter()
    print("Client Library Write: {time}s".format(time=client_write_end_time - client_write_start_time))

def print_formated_data(user_data):
    """Output the status log matched to the IP lookup table is a nice format"""
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
        print ("{:<15} {:<18} {:<15} {:<25} {:<17} {:<25}".format(name, IP, virt_ip, float(data_rec)*0.00000095367432, float(data_sent)*0.00000095367432, active_time))

def concat_syslogs():
    """Concatinates all syslog files into one temp file"""
    os.system("/bin/cat /var/log/syslog.7.gz /var/log/syslog.6.gz /var/log/syslog.5.gz /var/log/syslog.4.gz /var/log/syslog.3.gz /var/log/syslog.2.gz | /bin/gunzip > " + TMP_FILE_PATH)
    os.system("/bin/cat /var/log/syslog.1 /var/log/syslog >> " + TMP_FILE_PATH)

def get_con_datetime(date):
    """Converts the timestamp in syslog to miliseconds"""
    today = datetime.today()
    current_year = str(today.year)[2:]

    month = date[:3]
    the_rest = date[3:]

    if(month == "Jan"):
        date = "01" + the_rest +" " + str(current_year)
    elif(month == "Feb"):
        date = "02" + the_rest +" " + str(current_year)
    elif(month == "Mar"):
        date = "03" + the_rest +" " + str(current_year)
    elif(month == "Apr"):
        date = "04" + the_rest +" " + str(current_year)
    elif(month == "May"):
        date = "05" + the_rest +" " + str(current_year)
    elif(month == "Jun"):
        date = "06" + the_rest +" " + str(current_year)
    elif(month == "Jul"):
        date = "07" + the_rest +" " + str(current_year)
    elif(month == "Aug"):
        date = "08" + the_rest +" " + str(current_year)
    elif(month == "Sep"):
        date = "09" + the_rest +" " + str(current_year)
    elif(month == "Oct"):
        date = "10" + the_rest +" " + str(current_year)
    elif(month == "Nov"):
        date = "11" + the_rest +" " + str(current_year)
    elif(month == "Dec"):
        date = "12" + the_rest +" " + str(current_year)

    new_date = datetime.strptime(date, "%m %d %H:%M:%S %y")

    return new_date

def datetime_to_mili_two(date):
    """Converts the timestamp is status.log to miliseconds"""
    today = datetime.today()
    current_year = str(today.year)[2:]
    month = date[4:7]
    the_rest = date[7:20]

    if(month == "Jan"):
        date = "01" + the_rest + current_year
    elif(month == "Feb"):
        date = "02" + the_rest + current_year
    elif(month == "Mar"):
        date = "03" + the_rest + current_year
    elif(month == "Apr"):
        date = "04" + the_rest + current_year
    elif(month == "May"):
        date = "05" + the_rest + current_year
    elif(month == "Jun"):
        date = "06" + the_rest + current_year
    elif(month == "Jul"):
        date = "07" + the_rest + current_year
    elif(month == "Aug"):
        date = "08" + the_rest + current_year
    elif(month == "Sep"):
        date = "09" + the_rest + current_year
    elif(month == "Oct"):
        date = "10" + the_rest + current_year
    elif(month == "Nov"):
        date = "11" + the_rest + current_year
    elif(month == "Dec"):
        date = "12" + the_rest + current_year


    new_date = datetime.strptime(date, "%m %d %H:%M:%S %y")

    return round(new_date.timestamp() * 1000)

def help():
    """print out command line arguments"""
    print("Not Implemented")

def init_environment():
    """Initializes directories files and config and add cron job"""
    installed_path = os.path.dirname(os.path.realpath(__file__))

    temp_file_directory_path = installed_path + "/tmp/"
    IPLookup_file_directory_path = installed_path + "/IPLookup/"
    cache_data_file_directory_path = installed_path + "/cached_data/"

    try:
        os.mkdir(temp_file_directory_path)
    except:
        print(temp_file_directory_path + ": Dir Already Exists")

    try:
        os.mkdir(IPLookup_file_directory_path)
    except:
        print(IPLookup_file_directory_path + ": Dir Already Exists")

    try:
        os.mkdir(cache_data_file_directory_path)
    except:
        print(cache_data_file_directory_path + ": Dir Already Exists")

    temp_file_path = temp_file_directory_path + "tmp.txt"
    IPLookup_file_path = IPLookup_file_directory_path + 'IP_Table.json'
    cached_data_file_path = cache_data_file_directory_path + "cached_data.json"

    try:
        file = open(temp_file_path, "x")
        file.close()
    except:
        print("File Exists")
    try:
        file = open(IPLookup_file_path, "x")
        file.close()
    except:
        print("file Exists")

    try:
        file = open(cached_data_file_path, "x")
        file.close()
    except:
        print("File Exists")

    print("#################### Generating Config File ####################")
    config = {}
    config["org"] = input("Enter InfluxDB Organization Name: ")
    config["org_id"] = input("Enter InfluxDB Organization ID: ")
    config["token"] = input("Enter InfluxDB Token: ")
    config["url"] = input("Enter InfluxDB URL: ")
    config["tmp_path"] = temp_file_path
    config["ip_path"] = IPLookup_file_path
    config["cache_path"] = cached_data_file_path
    config["syslog"] = input("Enter syslog Path: ")
    config["vpn_status"] = input("Enter OpenVPN Status File Path: ")

    config_file = open(installed_path + "/config.json", "w")

    json.dump(config, config_file)

    cron_tab = CronTab(user='root')

    job_found = False
    for job in cron_tab:
        if job.comment == "OpenVPN Scrapper":
            job_found = True

    if job_found == False:
        new_job = cron_tab.new(command = "/usr/bin/python3 " + installed_path + "/OpenVPNLogging.py log", comment= "OpenVPN Scrapper")
        new_job.minute.every(1)
        cron_tab.write()

if __name__ == "__main__":
    main()
