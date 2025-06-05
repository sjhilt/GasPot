#######################################################################
# gaspot.py
#
# This is a 'honeypot' to record any commands that were provided to the
# system. This will record the connection, and if any attempts are made.
# This is a basic attempt, with lots of room for improvement.
#
# 03/24/21 - Changed to Python3 (finally)
# 06/04/25 - Updates to logging output to include raw command sent &
#               Updates the script to use F-Strings.
#
#   Authors: Kyle Wilhoit
#            Stephen Hilt
#            James M
#
########################################################################

import socket
import select
import datetime
import random
import configparser
import ast
import argparse
import os
import sys

# Argument parsing only takes care of a configuration file to be specified
parser = argparse.ArgumentParser()
parser.add_argument('--config', help='specify a configuration file to be read', required=False)
parser.add_argument('--log', help='specify a path to log to', required=False, default='all_attempts.log')
parser.add_argument('--quiet', help='be quiet; log only to the logfile and not STDOUT', dest='quiet', action='store_true')
parser.set_defaults(quiet=False)
args = parser.parse_args()

# Determine the configuration file to use
configuration_file = args.config if args.config else 'config.ini'

# Check if the configuration file actually exists; exit if not.
if not os.path.isfile(configuration_file):
    print('Please specify a configuration file or rename config.ini.dist to config.ini!')
    sys.exit(1)

# Reading configuration information
config = configparser.ConfigParser()
config.read(configuration_file)

# Set vars for connection information
TCP_IP = config.get('host', 'tcp_ip')
TCP_PORT = config.getint('host', 'tcp_port')
BUFFER_SIZE = config.get('host', 'buffer_size')
NOW = datetime.datetime.now(datetime.timezone.utc)
FILLSTART = NOW - datetime.timedelta(minutes=313)
FILLSTOP = NOW - datetime.timedelta(minutes=303)

# Get the localized decimal separator
DS = config.get('parameters', 'decimal_separator')

# Default Product names, changed based on config.ini file
PRODUCT1 = config.get('products', 'product1').ljust(22)
PRODUCT2 = config.get('products', 'product2').ljust(22)
PRODUCT3 = config.get('products', 'product3').ljust(22)
PRODUCT4 = config.get('products', 'product4').ljust(22)

# Create random Numbers for the volumes
#
# this will crate an initial Volume and then the second value based
# off the orig value.
min_vol = config.getint('parameters', 'min_vol')
max_vol = config.getint('parameters', 'max_vol')
Vol1 = random.randint(min_vol, max_vol)
vol1tc = random.randint(Vol1, Vol1 + 200)
Vol2 = random.randint(min_vol, max_vol)
vol2tc = random.randint(Vol2, Vol2 + 200)
Vol3 = random.randint(min_vol, max_vol)
vol3tc = random.randint(Vol3, Vol3 + 200)
Vol4 = random.randint(min_vol, max_vol)
vol4tc = random.randint(Vol4, Vol4 + 200)

# unfilled space ULLAGE
min_ullage = config.getint('parameters', 'min_ullage')
max_ullage = config.getint('parameters', 'max_ullage')
ullage1 = str(random.randint(min_ullage, max_ullage))
ullage2 = str(random.randint(min_ullage, max_ullage))
ullage3 = str(random.randint(min_ullage, max_ullage))
ullage4 = str(random.randint(min_ullage, max_ullage))

# Height of tank
min_height = config.getint('parameters', 'min_height')
max_height = config.getint('parameters', 'max_height')
height1 = f"{random.randint(min_height, max_height)}{DS}{random.randint(10, 99)}"
height2 = f"{random.randint(min_height, max_height)}{DS}{random.randint(10, 99)}"
height3 = f"{random.randint(min_height, max_height)}{DS}{random.randint(10, 99)}"
height4 = f"{random.randint(min_height, max_height)}{DS}{random.randint(10, 99)}"

# Water in tank, this is a variable that needs to be low
min_h2o = config.getint('parameters', 'min_h2o')
max_h2o = config.getint('parameters', 'max_h2o')
h2o1 = f"{random.randint(min_h2o, max_h2o)}{DS}{random.randint(10, 99)}"
h2o2 = f"{random.randint(min_h2o, max_h2o)}{DS}{random.randint(10, 99)}"
h2o3 = f"{random.randint(min_h2o, max_h2o)}{DS}{random.randint(10, 99)}"
h2o4 = f"{random.randint(min_h2o, max_h2o)}{DS}{random.randint(10, 99)}"

# Temperature of the tank, this will need to be between 50 - 60
low_temp = config.getint('parameters', 'low_temperature')
high_temp = config.getint('parameters', 'high_temperature')
temp1 = f"{random.randint(low_temp, high_temp)}{DS}{random.randint(10, 99)}"
temp2 = f"{random.randint(low_temp, high_temp)}{DS}{random.randint(10, 99)}"
temp3 = f"{random.randint(low_temp, high_temp)}{DS}{random.randint(10, 99)}"
temp4 = f"{random.randint(low_temp, high_temp)}{DS}{random.randint(10, 99)}"

# List for station name, add more names if you want to have this look less like a honeypot
# this should include a list of gas station names based on the country of demployement
station_name = ast.literal_eval(config.get("stations", "list"))
station = random.choice(station_name)

# This function is to set-up up the message to be sent upon a successful I20100 command being sent
# The final message is sent with a current date/time stamp inside of the main loop.
def I20100():
    return f"""
I20100
{station}

IN-TANK INVENTORY

TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP
  1  {PRODUCT1}{Vol1}      {vol1tc}     {ullage1}    {height1}     {h2o1}    {temp1}
  2  {PRODUCT2}{Vol2}      {vol2tc}     {ullage2}    {height2}     {h2o2}    {temp2}
  3  {PRODUCT3}{Vol3}      {vol3tc}     {ullage3}    {height3}     {h2o3}    {temp3}
  4  {PRODUCT4}{Vol4}      {vol4tc}     {ullage4}    {height4}     {h2o4}    {temp4}
{TIME.strftime('%m/%d/%Y %H:%M')}
"""

###########################################################################
#
# Only one Tank is listed currently in the I20200 command
#
###########################################################################
def I20200():
    return f"""
I20200

{station}

DELIVERY REPORT

T 1:{PRODUCT1}
INCREASE   DATE / TIME             GALLONS TC GALLONS WATER  TEMP DEG F  HEIGHT

      END: {FILLSTOP.strftime('%m/%d/%Y %H:%M')}         {Vol1 + 300}       {vol1tc + 300}   {h2o1}      {temp1}   {height1}
    START: {FILLSTART.strftime('%m/%d/%Y %H:%M')}         {Vol1 - 300}       {vol1tc - 300}   {h2o1}      {temp1}   {float(height1) - 23}
   AMOUNT:                          {Vol1}       {vol1tc}

{TIME.strftime('%m/%d/%Y %H:%M')}
"""

###########################################################################
#
# I20300 In-Tank Leak Detect Report
#
###########################################################################
def I20300():
    return f"""
I20300

{station}

TANK 1    {PRODUCT1}
    TEST STATUS: OFF
LEAK DATA NOT AVAILABLE ON THIS TANK

TANK 2    {PRODUCT2}
    TEST STATUS: OFF
LEAK DATA NOT AVAILABLE ON THIS TANK

TANK 3    {PRODUCT3}
    TEST STATUS: OFF
LEAK DATA NOT AVAILABLE ON THIS TANK

TANK 4    {PRODUCT4}
    TEST STATUS: OFF
LEAK DATA NOT AVAILABLE ON THIS TANK
{TIME.strftime('%m/%d/%Y %H:%M')}
"""

###########################################################################
# Shift report command I20400 only one item in report at this time,
# but can always add more if needed
###########################################################################
def I20400():
    return f"""
I20400

{station}

 SHIFT REPORT

SHIFT 1 TIME: 12:00 AM

TANK PRODUCT

  1  {PRODUCT1}                  VOLUME TC VOLUME  ULLAGE  HEIGHT  WATER   TEMP
SHIFT  1 STARTING VALUES      {Vol1}     {vol1tc}    {ullage1}   {height1}   {h2o1}    {temp1}
         ENDING VALUES        {Vol1 + 940}     {vol1tc + 886}    {int(ullage1) + 345}   {float(height1) + 53}  {h2o1}    {temp1}
         DELIVERY VALUE          0
         TOTALS                940
{TIME.strftime('%m/%d/%Y %H:%M')}
"""

###########################################################################
# I20500 In-Tank Status Report
###########################################################################
def I20500():
    return f"""
I20500

{station}

TANK   PRODUCT                 STATUS

  1    {PRODUCT1}                   NORMAL

  2    {PRODUCT2}                  HIGH WATER ALARM
                               HIGH WATER WARNING

  3    {PRODUCT3}                  NORMAL

  4    {PRODUCT4}                 NORMAL
{TIME.strftime('%m/%d/%Y %H:%M:%S.%f')}
"""

def log(mesg, destinations):
    now = datetime.datetime.now(datetime.timezone.utc)
    prefix = f"{now.strftime('%m/%d/%Y %H:%M:%S.%f')}: "
    for destination in destinations:
        destination.write(prefix + mesg)

log_destinations = [open(args.log, 'a', buffering=1)]
if not args.quiet:
    log_destinations.append(sys.stdout)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setblocking(0)
server_socket.bind((TCP_IP, TCP_PORT))
server_socket.listen(10)

#
# Infinite Loop to provide a connection available on port 10001
# This is the default port for the AVG's that were found online
# via R7's research.
#
#
active_sockets = [server_socket]
while True:
    readable, _, _ = select.select(active_sockets, [], [], 5)
    for conn in readable:
        if conn is server_socket:
            new_con, addr = server_socket.accept()
            new_con.settimeout(30.0)
            active_sockets.append(new_con)
        else:
            try:
                addr = conn.getpeername()
                TIME = datetime.datetime.now(datetime.timezone.utc)
                log(f"Connection from : {addr[0]}\n", log_destinations)
                response = conn.recv(4096)

                if not response:
                    active_sockets.remove(conn)
                    conn.close()
                    continue

                while not (b'\n' in response or b'00' in response):
                    response += conn.recv(4096)

                if response[0:2] == b"^A":
                    cmd = response.decode(errors='replace')[2:8]
                elif response[0:1] == b"\x01":
                    cmd = response.decode(errors='replace')[1:7]
                else:
                    log(f"Non ^A Command Attempt from: {addr[0]} - Raw command: {str(response)}\n", log_destinations)
                    conn.close()
                    active_sockets.remove(conn)
                    continue

                if len(response.decode(errors='replace')) < 6:
                    log(f"Invalid Command Attempt from: {addr[0]} - Raw command: {str(response)}\n", log_destinations)
                    conn.close()
                    active_sockets.remove(conn)
                    continue

                cmds = {
                    "I20100": I20100,
                    "I20200": I20200,
                    "I20300": I20300,
                    "I20400": I20400,
                    "I20500": I20500
                }

                if cmd in cmds:
                    log(f"Handling {cmd} Command Attempt from: {addr[0]}\n - Raw command: {str(response)}", log_destinations)
                    conn.send(cmds[cmd]().encode(errors='replace'))
                elif cmd.startswith("S6020"):
                    TEMP1 = ""
                    code = cmd[:6]
                    TEMP = response.split(code.encode(errors='replace'))
                    if len(TEMP) < 2:
                        conn.send("9999FF1B\n".encode(errors='replace'))
                    else:
                        TEMP1 = TEMP[1].rstrip(b"\r\n").decode(errors='replace')
                        formatted = TEMP1[:20] + "  " if len(TEMP1) > 22 else TEMP1.ljust(22)

                        if code == "S60201":
                            PRODUCT1 = formatted
                        elif code == "S60202":
                            PRODUCT2 = formatted
                        elif code == "S60203":
                            PRODUCT3 = formatted
                        elif code == "S60204":
                            PRODUCT4 = formatted
                        elif code == "S60200":
                            PRODUCT1 = PRODUCT2 = PRODUCT3 = PRODUCT4 = formatted
                        else:
                            conn.send("9999FF1B\n".encode(errors='replace'))
                            continue

                        log(f"{code}: {TEMP1} Command Attempt from: {addr[0]} - Raw command: {str(response)}\n", log_destinations)
                else:
                    conn.send("9999FF1B\n".encode(errors='replace'))
                    log(f"Attempt from: {addr[0]} with command: {str(response)}\n", log_destinations)
                    #log(f"Command Entered {response}\n", log_destinations)

            except OSError as OSerr:
                print(f"Error in OS Call: {str(OSerr)}")
                active_sockets.remove(conn)
                conn.close()
                continue
            except Exception as e:
                print(f"Unknown Error: {str(e)}")
                raise
            except KeyboardInterrupt:
                conn.close()
            except select.error:
                conn.close()
                for log_file in log_destinations:
                    log_file.close()

