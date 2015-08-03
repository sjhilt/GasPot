#######################################################################
# gaspot.py
#
# This is a 'honeypot' to record any commands that were provided to the
# system. This will record the connection, and if any attempts are made.
# This is a basic attempt, with lots of room for improvement.
#
#   Authors: Kyle Wilhoit
#            Stephen Hilt
#
########################################################################

import socket
import select
import datetime
import random

# Set vars for connection information
TCP_IP = '0.0.0.0'
TCP_PORT = 10001
BUFFER_SIZE = 1024
NOW = datetime.datetime.utcnow()
FILLSTART = NOW - datetime.timedelta(minutes=313)
FILLSTOP = NOW - datetime.timedelta(minutes=303)
# Default Product names, change based off country needs
PRODUCT1 = "SUPER".ljust(22)
PRODUCT2 = "UNLEAD".ljust(22)
PRODUCT3 = "DIESEL".ljust(22)
PRODUCT4 = "PREMIUM".ljust(22)

# Create random Numbers for the volumes
#
# this will crate an initial Volume and then the second value based
# off the orig value.
Vol1 = random.randint(1000, 9050)
vol1tc = random.randint(Vol1, Vol1+200)
Vol2 = random.randint(1000, 9050)
vol2tc = random.randint(Vol2, Vol2+200)
Vol3 = random.randint(1000, 9050)
vol3tc = random.randint(Vol3, Vol3+200)
Vol4 = random.randint(1000, 9050)
vol4tc = random.randint(Vol4, Vol4+200)

# unfilled space ULLAGE
ullage1 = str(random.randint(3000, 9999))
ullage2 = str(random.randint(3000, 9999))
ullage3 = str(random.randint(3000, 9999))
ullage4 = str(random.randint(3000, 9999))

# Height of tank
height1 = str(random.randint(25, 75)) + "." + str(random.randint(10, 99))
height2 = str(random.randint(25, 75)) + "." + str(random.randint(10, 99))
height3 = str(random.randint(25, 75)) + "." + str(random.randint(10, 99))
height4 = str(random.randint(25, 75)) + "." + str(random.randint(10, 99))

# Water in tank, this is a variable that needs to be low
h2o1 = str(random.randint(0, 9)) + "." + str(random.randint(10, 99))
h2o2 = str(random.randint(0, 9)) + "." + str(random.randint(10, 99))
h2o3 = str(random.randint(0, 9)) + "." + str(random.randint(10, 99))
h2o4 = str(random.randint(0, 9)) + "." + str(random.randint(10, 99))

# Temperature of the tank, this will need to be between 50 - 60
temp1 = str(random.randint(50, 60)) + "." + str(random.randint(10, 99))
temp2 = str(random.randint(50, 60)) + "." + str(random.randint(10, 99))
temp3 = str(random.randint(50, 60)) + "." + str(random.randint(10, 99))
temp4 = str(random.randint(50, 60)) + "." + str(random.randint(10, 99))

# List for station name, add more names if you want to have this look less like a honeypot
# this should include a list of gas station names based on the country of demployement
# ***** CHANGE THESE ******
station_name = ['EXXON STATION\n    12 Fake St\n    Anytown, MO 12346', 'FUEL COOP',
                'SHELL STATION', 'AMOCO FULES', 'MOBIL STATION', 'MARATHON GAS',
                'CHEVRON STATION', 'CITGO FUELS', 'BP FUELS', 'PILOT TRUCK STOP',
                'FLYING J TRUCK STOP', 'LOVES FUEL STATION', ' SINCLAIR FUEL',
                'VICTORY OIL', 'CONOCO FUELS', '76 OIL', 'TEXACO STATION', 'PETRO-CANADA',
                'TOTAL PETROL', 'HEM PETROL', 'ARAL PETROL', 'OBERT 24h', 'AGIP PETROL',
                'ROMPETROL STATION', 'PETRON STATION', 'STATOIL STATION', 'LUK OIL',
                'MURPHY OIL', ]
slength = len(station_name)
station = station_name[random.randint(0, slength-1)]

# This function is to set-up up the message to be sent upon a successful I20100 command being sent
# The final message is sent with a current date/time stamp inside of the main loop.
def I20100():
    I20100_1 = '''
I20100
'''
    I20100_2 = '''

    ''' + station + '''



IN-TANK INVENTORY

TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP
  1  '''+ PRODUCT1 + '''''' + str(Vol1) + '''      '''+ str(vol1tc) +'''     '''+ ullage1 +'''    '''+ height1 +'''     '''+ h2o1 +'''    '''+ temp1 +'''
  2  '''+ PRODUCT2 + '''''' + str(Vol2) + '''      '''+ str(vol2tc) +'''     '''+ ullage2 +'''    '''+ height2 +'''     '''+ h2o2 +'''    '''+ temp2 +'''
  3  '''+ PRODUCT3 + '''''' + str(Vol3) + '''      '''+ str(vol3tc) +'''     '''+ ullage3 +'''    '''+ height3 +'''     '''+ h2o3 +'''    '''+ temp3 +'''
  4  '''+ PRODUCT4 + '''''' + str(Vol4) + '''      '''+ str(vol4tc) +'''     '''+ ullage4 +'''    '''+ height4 +'''     '''+ h2o4 +'''    '''+ temp4 +'''
'''
    return I20100_1 + str(TIME.strftime('%m/%d/%Y %H:%M')) + I20100_2




###########################################################################
#
# Only one Tank is listed currently in the I20200 command
#
###########################################################################
def I20200():
    I20200_1 = '''
I20200
'''
    I20200_2 = '''


''' + station + '''


DELIVERY REPORT

T 1:'''+ PRODUCT1 +'''
INCREASE   DATE / TIME             GALLONS TC GALLONS WATER  TEMP DEG F  HEIGHT

      END: '''+ str(FILLSTOP.strftime('%m/%d/%Y %H:%M')) +'''         '''+ str(Vol1 + 300) +'''       '''+ str(vol1tc + 300) +'''   '''+ h2o1 +'''      '''+ temp1 +'''   '''+ height1 +'''
    START: '''+ str(FILLSTART.strftime('%m/%d/%Y %H:%M')) +'''         '''+ str(Vol1 - 300) +'''       '''+ str(vol1tc - 300) +'''   '''+ h2o1 +'''      '''+ temp1 +'''   '''+ str(float(height1) - 23) +'''
   AMOUNT:                          '''+ str(Vol1)+'''       '''+ str(vol1tc) +'''

'''
    return I20200_1 + str(TIME.strftime('%m/%d/%Y %H:%M')) + I20200_2


###########################################################################
#
# I20300 In-Tank Leak Detect Report
#
###########################################################################
def I20300():
    I20300_1 = '''
I20300
'''
    I20300_2 = '''

''' + station + '''


TANK 1    '''+ PRODUCT1 +'''           
    TEST STATUS: OFF   
LEAK DATA NOT AVAILABLE ON THIS TANK


TANK 2    '''+ PRODUCT2 +'''           
    TEST STATUS: OFF   
LEAK DATA NOT AVAILABLE ON THIS TANK


TANK 3    '''+ PRODUCT3 +'''
    TEST STATUS: OFF   
LEAK DATA NOT AVAILABLE ON THIS TANK


TANK 4    '''+ PRODUCT4 +'''
    TEST STATUS: OFF
LEAK DATA NOT AVAILABLE ON THIS TANK
'''
    return I20300_1 + str(TIME.strftime('%m/%d/%Y %H:%M')) + I20300_2

###########################################################################
# Shift report command I20400 only one item in report at this time, 
# but can always add more if needed
###########################################################################
def I20400():
    I20400_1 = '''
I20400
'''
    I20400_2 = '''

''' + station + '''


 SHIFT REPORT 

SHIFT 1 TIME: 12:00 AM        

TANK PRODUCT

  1  '''+ PRODUCT1 +'''                  VOLUME TC VOLUME  ULLAGE  HEIGHT  WATER   TEMP
SHIFT  1 STARTING VALUES      ''' + str(Vol1) +'''     '''+ str(vol1tc) +'''    '''+ ullage1 +'''   '''+ height1 +'''   '''+ h2o1 +'''    '''+ temp1 +'''
         ENDING VALUES        ''' + str(Vol1 + 940) +'''     '''+ str(vol1tc + 886) +'''    '''+ str(int(ullage1) + 345) +'''   '''+ str(float(height1) + 53)+'''  '''+ h2o1 +'''    '''+ temp1 +''' 
         DELIVERY VALUE          0
         TOTALS                940

'''
    return I20400_1 + str(TIME.strftime('%m/%d/%Y %H:%M')) + I20400_2
###########################################################################
# I20500 In-Tank Status Report
###########################################################################
def I20500():
    I20500_1 = '''
I20500
'''
    I20500_2 = '''


''' + station + '''


TANK   PRODUCT                 STATUS

  1    '''+ PRODUCT1 +'''                   NORMAL

  2    '''+ PRODUCT2 +'''                  HIGH WATER ALARM   
                               HIGH WATER WARNING 

  3    '''+ PRODUCT3 +'''                  NORMAL

  4    '''+ PRODUCT4 +'''                 NORMAL
'''
    return I20500_1 + str(TIME.strftime('%m/%d/%Y %H:%M')) + I20500_2

# create the socket, bind, and start listening for incoming connections
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
    readable, writeable, errored = select.select(active_sockets, [], [], 5)
    for conn in readable:
        if conn is server_socket:
            new_con, addr = server_socket.accept()
            new_con.settimeout(30.0)
            active_sockets.append(new_con)
        else:
            addr = conn.getpeername()
            try:
                # get current time in UTC
                TIME = datetime.datetime.utcnow()
                # open log file for recording messages
                target = open("all_attempts.log", 'a')
                # write out initial connection
                target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                    "- Connection from : %s\n" % addr[0])
                # Get the initial data
                response = conn.recv(4096)
                # The connection has been closed
                if not response:
                    active_sockets.remove(conn)
                    conn.close()
                    continue
                
                while not ('\n' in response or '00' in response):
                    response += conn.recv(4096)
                # if first value is not ^A then do nothing
                # thanks John(achillean) for the help
                if response[0] != '\x01':
                    target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                        " - Non ^A Command Attempt from: %s\n" % addr[0])
                    conn.close()
                    active_sockets.remove(conn)
                    continue
                # if response is less than 6, than do nothing
                if len(response) < 6:
                    target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                        " - Non Valid Command Attempt from: %s\n" % addr[0])
                    conn.close()
                    active_sockets.remove(conn)
                    continue

                cmds = {"I20100" : I20100, "I20200" : I20200, "I20300" : I20300 , "I20400" : I20400, "I20500" : I20500}
                cmd = response[1:7] # strip ^A and \n out

                if cmd in cmds:
                    target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                        " - %s Command Attempt from: %s\n" % (cmds[cmd], addr[0]))
                    conn.send(cmds[cmd]())
                elif cmd.startswith("S6020"):
                    # change the tank name
                    if cmd.startswith("S60201"):
                        # split string into two, the command, and the data
                        TEMP = response.split('S60201')
                        # if length is less than two, print error
                        if len(TEMP) < 2:
                            conn.send("9999FF1B\n")
                        # Else the command was entered correctly and continue 
                        else:
                            # Strip off the carrage returns and new lines
                            TEMP1 = TEMP[1].rstrip("\r\n")
                            # if Length is less than 22
                            if len(TEMP1) < 22:
                                # pad the result to have 22 chars
                                PRODUCT1 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                # else only print 22 chars if the result was longer
                                PRODUCT1 = TEMP1[:20] + "  "
                            else:
                                # else it fits fine (22 chars)
                                PRODUCT1 = TEMP1
                        #log result 
                        target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                            " - S60201: "+ TEMP1 +" Command Attempt from: %s\n" % addr[0])
                    # Follows format for S60201 for comments
                    elif cmd.startswith("S60202"):
                        TEMP = response.split('S60202')
                        if len(TEMP) < 2:
                            conn.send("9999FF1B\n")
                        else:
                            TEMP1 = TEMP[1].rstrip("\r\n")
                            if len(TEMP1) < 22:
                                PRODUCT2 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                PRODUCT2 = TEMP1[:20] + "  "
                            else:
                                PRODUCT2 = TEMP1
                        target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                            " - S60202: "+ TEMP1 +" Command Attempt from: %s\n" % addr[0])
                    # Follows format for S60201 for comments
                    elif cmd.startswith("S60203"):
                        TEMP = response.split('S60203')
                        if len(TEMP) < 2:
                            conn.send("9999FF1B\n")
                        else:
                            TEMP1 = TEMP[1].rstrip("\r\n")
                            if len(TEMP1) < 22:
                                PRODUCT3 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                PRODUCT3 = TEMP1[:20] + "  "
                            else:
                                PRODUCT3 = TEMP1
                        target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                            " - S60203: "+ TEMP1 +" Command Attempt from: %s\n" % addr[0])
                    # Follows format for S60201 for comments
                    elif cmd.startswith("S60204"):
                        TEMP = response.split('S60204')
                        if len(TEMP) < 2:
                            conn.send("9999FF1B\n")
                        else:
                            TEMP1 = TEMP[1].rstrip("\r\n")
                            if len(TEMP1) < 22:
                                PRODUCT4 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                PRODUCT4 = TEMP1[:20] + "  "
                            else:
                                PRODUCT4 = TEMP1
                        target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                            " - S60204: "+ TEMP1 +" Command Attempt from: %s\n" % addr[0])
                    # Follows format for S60201 for comments
                    elif cmd.startswith("S60200"):
                        TEMP = response.split('S60200')
                        if len(TEMP) < 2:
                            # 9999 indicates that the command was not understood and
                            # FF1B is the checksum for the 9999
                            conn.send("9999FF1B\n")
                        else:
                            TEMP1 = TEMP[1].rstrip("\r\n")
                            if len(TEMP1) < 22:
                                PRODUCT1 = TEMP1.ljust(22)
                                PRODUCT2 = TEMP1.ljust(22)
                                PRODUCT3 = TEMP1.ljust(22)
                                PRODUCT4 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                PRODUCT1 = TEMP1[:20] + "  "
                                PRODUCT2 = TEMP1[:20] + "  "
                                PRODUCT3 = TEMP1[:20] + "  "
                                PRODUCT4 = TEMP1[:20] + "  "
                            else:
                                PRODUCT1 = TEMP1
                                PRODUCT2 = TEMP1
                                PRODUCT3 = TEMP1
                                PRODUCT4 = TEMP1
                        target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                            " - S60200: "+ TEMP1 +" Command Attempt from: %s\n" % addr[0])
                    else:
                        conn.send("9999FF1B\n")
                # Else it is a currently unsupported command so print the error message found in the manual
                # 9999 indicates that the command was not understood and FF1B is the checksum for the 9999
                else:
                    conn.send("9999FF1B\n")
                    # log what was entered
                    target.write(str(datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M')) + \
                        " - Attempt from: %s\n" % addr[0])
                    target.write("       Command Entered %s\n" % response)
            except Exception, e:
                print 'Unknown Error: {}'.format(str(e))
                raise
            except KeyboardInterrupt:
                conn.close()
            except select.error:
                conn.close()
                # close log file
                target.close()
