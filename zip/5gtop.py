#!/usr/bin/env python
#-*- coding: utf-8 -*-

"""
Identification
--------------
    5gtop
    Monitor operation of Huawei 4G/5G modems
    
    Author
    PDO Smith
    
    License
    GPL 3
"""

"""
Acknowledgements
----------------
    This program uses the API produced by Salamek:  
    https://github.com/Salamek/huawei-lte-api  

    and the file pager 'slit' from tigrawap  
    https://github.com/tigrawap/slit

    This program(5gtop) is a derivative of
    https://github.com/octave21/huawei-lte
"""



#-----------------------------------------------------------------------

class Settings(object):
    def __init__(self,**kwargs):
        self.__dict__.update(kwargs)
        
#-----------------------------------------------------------------------

stg = Settings()
stg.version   = "1.0.0"
stg.debug     = 1
stg.test_time = 15
stg.restart_delay = 6
stg.rsrp_min  = -141
stg.rsrq_min  = -34.0
stg.heartbeat = 10.0
stg.user      = 'admin'

#------------------------------------------------------------------------------------------------------
# Setup logging
#------------------------------------------------------------------------------------------------------
import logging
from logging.handlers import TimedRotatingFileHandler

formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)02d   %(message)s', datefmt='%d-%b-%y %H:%M:%S')

handler = TimedRotatingFileHandler('signal-log.txt', when='midnight',backupCount=30)
handler.setFormatter(formatter)
handler.suffix = "%Y%m%d"
logger = logging.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

logger.info('Program startup')

#-----------------------------------------------------------------------

import importlib.util
import sys,os,subprocess,time
import platform

#$(cat "/proc/$PPID/comm")
#res = subprocess.run(['cat', '/proc/$PPID/comm'], capture_output=True, text=True).stdout

#-----------------------------------------------------------------------

def check_linux_requirements():
    
    reqs=[]
    missing_libs=[]
    missing_files=[]
    libs = ['sys','pdb','os','base64','time','datetime','locale','traceback','curses','math','ipaddress','signal','plmn', \
    'urllib','threading','huawei_lte_api','icmplib','typing','argparse','pprint','logging','subprocess','atexit','trace']
       
    for lib in libs:
        spec = importlib.util.find_spec(lib)
        found = spec is not None
        if not found:
            missing_libs.append(lib)
    if len(missing_libs) > 0:
        reqs.append('-----missing libraries------------')
        for l in missing_libs:
            reqs.append(l)
        reqs.append("Install them using pip or pip3")

    if sys.version_info >= (3,8):
        pass
    else:
        reqs.append("-----Wrong python version---------")
        reqs.append(F"Old version of python found {sys.version}")
        reqs.append(F"must be greater than or equal to 3.8")
    
    if not subprocess.run(['which','wmctrl'], capture_output=True, text=True).stdout:
        reqs.append("--------------wmctrl--------------")
        reqs.append("wmctrl is not installed")
        reqs.append("Use your package manager to install it")
            
    if not os.path.isfile("./slit"):
        missing_files.append('slit')

    if not os.path.isfile("./README.md"):
        missing_files.append('README.md')
    if not os.path.isfile("./help.txt"):
        missing_files.append('help.txt')
        
    if len(missing_files) > 0:
        reqs.append("-----Missing files----------------")
        for m in missing_files:
            reqs.append(m)
        
    res = subprocess.run(['sysctl', 'net.ipv4.ping_group_range'], capture_output=True, text=True).stdout
    eq = res.find('=')
    rnge = res[eq+1:]
    tab= rnge.find('\t')
    r1 = int(rnge[0:tab])
    r2 = int(rnge[tab+1:])
    if r1 != 0 or r2 != 2147483647:
        reqs.append("-----Ping settings incorrect------")
        reqs.append("Ping group range missing or incorrect")
        reqs.append("Please issue the following two commands:")
        reqs.append("echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee -a /etc/sysctl.conf")
        reqs.append("sudo sysctl -p")

    if len(reqs) > 0:
        print("---------------------------------------------------")
        print("Requirements for 5gtop were not satisfied")
        print("---------------------------------------------------")
        print("")
        for r in reqs:
            print(r)
            logger.info(r)
        print("")
        print("---------------------------------------------------")
        print("Please correct these items before 5gtop can start up")
        print("---------------------------------------------------")
        sys.exit(0)
    else:
        logger.info("All requirements for 5gtop were satisfied")

#-----------------------------------------------------------------------

def check_windows_requirements():

    reqs=[]
    missing_libs=[]
    missing_files=[]
    libs = ['sys','pdb','os','base64','time','datetime','locale','traceback','curses','math','ipaddress','signal','plmn', \
    'urllib','threading','huawei_lte_api','icmplib','typing','argparse','pprint','logging','subprocess','atexit','trace']
       
    for lib in libs:
        spec = importlib.util.find_spec(lib)
        found = spec is not None
        if not found:
            missing_libs.append(lib)
    if len(missing_libs) > 0:
        reqs.append('-----missing libraries------------')
        for l in missing_libs:
            reqs.append(l)
        reqs.append("Install them using pip or pip3")

    if sys.version_info >= (3,8):
        pass
    else:
        reqs.append("-----Wrong python version---------")
        reqs.append(F"Old version of python found {sys.version}")
        reqs.append(F"must be greater than or equal to 3.8")
    
    if not os.path.isfile("./5gtop.bat"):
        missing_files.append('5gtop.bat')           
    if not os.path.isfile("./slit.exe"):
        missing_files.append('slit.exe')
    if not os.path.isfile("./about.txt"):
        missing_files.append('about.txt')
    if not os.path.isfile("./help.txt"):
        missing_files.append('help.txt')
        
    if len(missing_files) > 0:
        reqs.append("-----Missing files----------------")
        for m in missing_files:
            reqs.append(m)

    if len(reqs) > 0:
        print("---------------------------------------------------")
        print("Requirements for 5gtop were not satisfied")
        print("---------------------------------------------------")
        print("")
        for r in reqs:
            print(r)
            logger.info(r)
        print("")
        print("---------------------------------------------------")
        print("Please correct these items before 5gtop can start up")
        print("---------------------------------------------------")
        sys.exit(0)
    else:
        logger.info("All requirements for 5gtop in Windows were satisfied")
    
#-----------------------------------------------------------------------

if platform.system() == "Linux":
    check_linux_requirements()
elif platform.system() == "Windows":
    check_windows_requirements()
else:
    logger.info("Platform not identified, now flying on a wing and a prayer")


import sys, pdb, os, base64, time, datetime, locale, traceback, curses, math, ipaddress, signal
import urllib.request, urllib.parse, urllib.error
from threading import Thread, Event
import threading
#import kthread
from os.path import basename
from huawei_lte_api.Client import Client
from huawei_lte_api.AuthorizedConnection import AuthorizedConnection
from huawei_lte_api.Connection import Connection
from huawei_lte_api.enums.device import  ControlModeEnum
from icmplib import ping, multiping, traceroute, resolve
from icmplib import ICMPLibError, NameLookupError, ICMPSocketError
from typing import Any, Callable
from argparse import ArgumentParser
import pprint
import subprocess
import atexit
import trace
try:
    import plmn
except:
    logger.info("Missing file or bad entry in plmn.py")

WINDOW_TITLE = ":ACTIVE:"
stg.win_xpos = 0
stg.win_ypos = 0
stg.win_width_px  = 1250
stg.win_height_px = 660
stg.win_width     = 130 #cols ----
stg.win_height    = 30  #rows ----            

if platform.system() == "Linux":
    subprocess.run(["wmctrl", "-r", WINDOW_TITLE, "-e", F"0,{stg.win_xpos},{stg.win_ypos},{stg.win_width_px},{stg.win_height_px}"])
elif platform.system() == "Windows":
    cmd = F'mode con: cols={stg.win_width} lines={stg.win_height}'
    os.system(cmd)

#-----------------------------------------------------------------------
# Format dump data
#-----------------------------------------------------------------------
def dump(method: Callable[[], Any]) -> None:
    #print("==== %s" % method.__qualname__)
    try:       
        with open("modem-data.txt", "a") as dump_file:
            pprint.pprint(method(), dump_file)
    except  Exception as e:
        pass
        #dprint(F"Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",2)
    #print("")

#-----------------------------------------------------------------------

def dump_data():
        global mdm
        mdm.status = "Busy dumping modem internal data"
        logger.info("Data dump in progress")
        try:
            with Connection(F"http://{mdm.modem_ip}", username=F'{stg.user}', password=mdm.password ) as connection:
                client = Client(connection)
                if os.path.isfile("modem-data.txt"):
                    os.remove("modem-data.txt")
                dump(client.device.information)
                dump(client.device.autorun_version)
                dump(client.device.device_feature_switch)
                dump(client.device.basic_information)
                dump(client.device.basicinformation)
                dump(client.device.usb_tethering_switch)
                dump(client.device.boot_time)
                dump(client.device.signal)
                dump(client.device.antenna_status)
                dump(client.device.antenna_type)
                dump(client.device.logsetting)

                dump(client.user.state_login)
                dump(client.user.remind)
                dump(client.user.password)
                dump(client.user.pwd)
                dump(client.user.authentication_login)
                dump(client.user.challenge_login)
                dump(client.user.hilink_login)
                dump(client.user.history_login)
                dump(client.user.heartbeat)
                dump(client.user.web_feature_switch)
                dump(client.user.screen_state)
                dump(client.user.session)

                dump(client.monitoring.converged_status)
                dump(client.monitoring.status)
                dump(client.monitoring.check_notifications)
                dump(client.monitoring.traffic_statistics)
                dump(client.monitoring.start_date)
                dump(client.monitoring.start_date_wlan)
                dump(client.monitoring.month_statistics)
                dump(client.monitoring.month_statistics_wlan)
                dump(client.monitoring.wifi_month_setting)
                dump(client.monitoring.daily_data_limit)
                dump(client.monitoring.statistic_feature_switch)

                dump(client.security.bridgemode)
                dump(client.security.get_firewall_switch)
                dump(client.security.mac_filter)
                dump(client.security.lan_ip_filter)
                dump(client.security.virtual_servers)
                dump(client.security.url_filter)
                dump(client.security.upnp)
                dump(client.security.dmz)
                dump(client.security.sip)
                dump(client.security.feature_switch)
                dump(client.security.nat)
                dump(client.security.special_applications)
                dump(client.security.white_lan_ip_filter)
                dump(client.security.white_url_filter)
                dump(client.security.acls)

                dump(client.webserver.publickey)
                dump(client.webserver.token)
                dump(client.webserver.white_list_switch)

                dump(client.global_.module_switch)

                dump(client.wlan.wifi_feature_switch)
                dump(client.wlan.station_information)
                dump(client.wlan.basic_settings)
                dump(client.wlan.security_settings)
                dump(client.wlan.multi_security_settings)
                dump(client.wlan.multi_security_settings_ex)
                dump(client.wlan.multi_basic_settings)
                dump(client.wlan.host_list)
                dump(client.wlan.handover_setting)
                dump(client.wlan.multi_switch_settings)
                dump(client.wlan.multi_macfilter_settings)
                dump(client.wlan.multi_macfilter_settings_ex)
                dump(client.wlan.mac_filter)
                dump(client.wlan.oled_showpassword)
                dump(client.wlan.wps)
                dump(client.wlan.wps_appin)
                dump(client.wlan.wps_pbc)
                dump(client.wlan.wps_switch)
                dump(client.wlan.status_switch_settings)
                dump(client.wlan.wifiprofile)
                dump(client.wlan.wififrequence)
                dump(client.wlan.wifiscanresult)
                dump(client.wlan.wlandbho)
                dump(client.wlan.wlanintelligent)

                dump(client.cradle.status_info)
                dump(client.cradle.feature_switch)
                dump(client.cradle.basic_info)
                dump(client.cradle.factory_mac)
                dump(client.cradle.mac_info)

                dump(client.pin.status)
                dump(client.pin.simlock)
                dump(client.pin.save_pin)

                dump(client.language.current_language)
                dump(client.config_device_information.config)
                dump(client.config_dialup.config)
                dump(client.config_dialup.connectmode)
                dump(client.config_dialup.profileswitch)
                dump(client.config_dialup.lmt_auto_mode_disconnect)

                dump(client.config_global.languagelist)
                dump(client.config_global.config)
                dump(client.config_global.net_type)
                dump(client.config_lan.config)
                dump(client.config_network.config)
                dump(client.config_network.net_mode)
                dump(client.config_network.networkmode)
                dump(client.config_network.networkband_null)

                dump(client.config_pc_assistant.config)
                dump(client.config_pc_assistant.updateautorun)

                dump(client.config_pincode.config)
                dump(client.config_sms.config)

                dump(client.config_voice.config)

                dump(client.config_web_ui_cfg.config)

                dump(client.config_wifi.configure)
                dump(client.config_wifi.country_channel)
                dump(client.config_wifi.channel_auto_match_hardware)

                dump(client.config_device.config)
                dump(client.config_fast_boot.config)
                dump(client.config_firewall.config)
                dump(client.config_ipv6.config)
                dump(client.config_ota.config)
                dump(client.config_pb.config)
                dump(client.config_sntp.config)
                dump(client.config_statistic.config)
                dump(client.config_stk.config)
                dump(client.config_update.config)
                dump(client.config_u_pnp.config)
                dump(client.config_ussd.prepaidussd)
                dump(client.config_ussd.postpaidussd)
                dump(client.config_web_sd.config)
                dump(client.usermanual_public_sys_resources.config)
                dump(client.ota.status)

                dump(client.net.current_plmn)
                dump(client.net.net_mode)
                dump(client.net.network)
                dump(client.net.register)
                dump(client.net.net_mode_list)
                # DoS? dump(client.net.plmn_list)
                dump(client.net.net_feature_switch)
                dump(client.net.cell_info)
                dump(client.net.csps_state)

                dump(client.dial_up.mobile_dataswitch)
                dump(client.dial_up.connection)
                dump(client.dial_up.dialup_feature_switch)
                dump(client.dial_up.profiles)
                dump(client.dial_up.auto_apn)

                dump(client.sms.get_cbsnewslist)
                dump(client.sms.sms_count)
                dump(client.sms.send_status)
                dump(client.sms.get_sms_list)
                dump(client.sms.config)
                dump(client.sms.sms_count_contact)
                dump(client.sms.get_sms_list_pdu)
                dump(client.sms.sms_list_contact)

                dump(client.redirection.homepage)

                dump(client.v_sim.operateswitch_vsim)

                dump(client.dhcp.settings)
                dump(client.dhcp.feature_switch)
                dump(client.dhcp.dhcp_host_info)
                dump(client.dhcp.static_addr_info)

                dump(client.d_dns.get_ddns_list)
                dump(client.d_dns.get_status)
                dump(client.d_dns.serverlist)

                dump(client.diagnosis.trace_route_result)
                dump(client.diagnosis.diagnose_ping)
                dump(client.diagnosis.diagnose_traceroute)
                dump(client.diagnosis.time_reboot)

                dump(client.s_ntp.get_settings)
                dump(client.s_ntp.sntpswitch)
                dump(client.s_ntp.serverinfo)
                dump(client.s_ntp.timeinfo)

                dump(client.online_update.check_new_version)
                dump(client.online_update.status)
                dump(client.online_update.url_list)
                dump(client.online_update.ack_newversion)
                # May cause device reboot: dump(client.online_update.cancel_downloading)
                dump(client.online_update.upgrade_messagebox)
                dump(client.online_update.configuration)
                dump(client.online_update.autoupdate_config)
                dump(client.online_update.redirect_cancel)

                dump(client.log.loginfo)

                dump(client.time.timeout)

                dump(client.sd_card.dlna_setting)
                dump(client.sd_card.sdcard)
                dump(client.sd_card.sdcardsamba)
                dump(client.sd_card.printerlist)
                dump(client.sd_card.share_account)

                dump(client.usb_storage.fsstatus)
                dump(client.usb_storage.usbaccount)

                dump(client.usb_printer.printerlist)

                dump(client.vpn.feature_switch)
                dump(client.vpn.br_list)
                dump(client.vpn.ipsec_settings)
                dump(client.vpn.l2tp_settings)
                dump(client.vpn.pptp_settings)
                dump(client.vpn.status)

                dump(client.ntwk.lan_upnp_portmapping)
                dump(client.ntwk.celllock)
                dump(client.ntwk.dualwaninfo)

                dump(client.pb.get_pb_list)
                dump(client.pb.pb_count)
                dump(client.pb.group_count)

                dump(client.syslog.querylog)

                dump(client.voice.featureswitch)
                dump(client.voice.sipaccount)
                dump(client.voice.sipadvance)
                dump(client.voice.sipserver)
                dump(client.voice.speeddial)
                dump(client.voice.functioncode)
                dump(client.voice.voiceadvance)
                dump(client.voice.codec)

                dump(client.cwmp.basic_info)

                dump(client.lan.host_info)

                dump(client.led.nightmode)
                dump(client.led.appctrlled)

                dump(client.statistic.feature_roam_statistic)

                dump(client.timerule.timerule)

                dump(client.bluetooth.settings)
                dump(client.bluetooth.scan)

                dump(client.mlog.mobile_logger)

                dump(client.voice.voicebusy)

                dump(client.staticroute.wanpath)

                dump(client.system.devcapacity)
                dump(client.system.deviceinfo)
                dump(client.system.onlineupg)

                dump(client.app.operatorinfo)
                dump(client.app.privacypolicy)
        except:
            pass
            #dprint(F"Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",2)
        logger.info("Data dump in completed")

#-----------------------------------------------------------------------



#-----------------------------------------------------------------------

class KThread(threading.Thread):
  """A subclass of threading.Thread, with a kill()
method."""
  def __init__(self, *args, **keywords):
    threading.Thread.__init__(self, *args, **keywords)
    self.killed = False

  def start(self):
    """Start the thread."""
    self.__run_backup = self.run
    self.run = self.__run     
    threading.Thread.start(self)

  def __run(self):
    """Hacked run function, which installs the
trace."""
    sys.settrace(self.globaltrace)
    self.__run_backup()
    self.run = self.__run_backup

  def globaltrace(self, frame, why, arg):
    if why == 'call':
      return self.localtrace
    else:
      return None

  def localtrace(self, frame, why, arg):
    if self.killed:
      if why == 'line':
        raise SystemExit()
    return self.localtrace

  def kill(self):
    self.killed = True

#-----------------------------------------------------------------------
# Keyboard loop
#-----------------------------------------------------------------------

class Keyboard(Thread) :
    def __init__(self) :
        Thread.__init__(self)
    def run(self):
        global cmd
        global display_data_event

        try:
            while not cmd.stop :
                c = stdscr.getch()
                display_data_event.set()
                if c == ord('q'):
                    logger.info("Quit command")
                    cmd.stop = True
                if c == ord('r'):
                    logger.info("Reboot command")
                    cmd.reboot = True
                if c == ord('d'):
                    logger.info("Dump modem data command")
                    cmd.show_modem_data = True
                if c == ord('h'):
                    logger.info("Help command")
                    cmd.show_help = True
                if c == ord('m'):
                    logger.info("Modem log command command")
                    cmd.show_modem_log = True
                if c == ord('s'):
                    logger.info("Signal log command")
                    cmd.show_signal_log = True
                if c == ord('a'):
                    logger.info("About command")
                    cmd.show_about = True
                if c == ord('t'):
                    logger.info("Test command")
                    cmd.test = True
                    
                process_keyboard_commands()
                
        except  Exception as e:
            dprint(F"(1) Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",2)
            cmd.stop = True

#-----------------------------------------------------------------------
# Modem heartbeat loop
# kill and restart the modem thread if it stops responding for 10 seconds ----
#-----------------------------------------------------------------------

class ModemHeartbeat(Thread) :
    def __init__(self) :
        Thread.__init__(self)
    def run(self):

        global cmd
        global mdm
        global modem_thread
        global connection
        
        while not cmd.stop:
            time.sleep(mdm.interval + 0.1)
            start = time.time()
            heartbeat_event.wait(mdm.interval + stg.heartbeat)
            finish = time.time()
            if finish - start > mdm.interval + stg.heartbeat - 1:
                #connection.close()
                modem_thread.kill()
                logger.info(F"Heartbeat killed modem thread {mdm.modem_id}")
                mdm.status = F"Heartbeat killed modem thread {mdm.modem_id}"
                modem_thread      = KThread(target=monitor_modem)
                modem_thread.name = 'Modem'
                modem_thread.start()
                # get the thread ID ----
                for thread in threading.enumerate():
                    thread_name =thread.name
                    thread_ident=thread.native_id
                    if thread_name == 'Modem':
                        mdm.modem_id = thread_ident
                logger.info(F"Restarted modem thread {mdm.modem_id}")
                mdm.status = F"Restarted modem thread {mdm.modem_id}"
            mdm.heartbeat = finish-start
                
#-----------------------------------------------------------------------
# Ping url loop
#-----------------------------------------------------------------------

class Ping(Thread) :
    def __init__(self,h) :
        Thread.__init__(self)
        self.h = h
    def run(self):

        global png
        
        #interval=self.h
        
        if png.ping_ip != 0:
            while not cmd.stop:
                start = time.time()
                try :
                    host = ping(png.ping_ip, count=1, interval=png.interval, privileged=False)
                    if host.is_alive:
                        png.time = host.avg_rtt
                    else:
                        png.time = -1
                except Exception as e :
                    png.time = -2
                finish = time.time()
                elapsed_time = finish - start
                if elapsed_time < png.interval:
                    time.sleep(png.interval - elapsed_time)

#-----------------------------------------------------------------------------------------------------
# Modem scan loop
#-----------------------------------------------------------------------------------------------------
'''
class ModemMonitor(Thread) :
    def __init__(self) :
        Thread.__init__(self)
    def run(self):

        cycle = 0
        reboot = False
        
        global cmd
        global mdm
        global client
        global display_data_event
        #connection = None
        #client = None
        global connection
        global client

        bar  = "                                                                                                                                                                                      "
        dash = "----------------------------------------------------------------------------------------------------------"
        elapsed_time = 1.0
        
        while not cmd.stop:
            mdm.heartbeat = 1
            if elapsed_time < mdm.interval:
                time.sleep(mdm.interval - elapsed_time)
                
            modem_loop_start = time.time()
            display_data_event.set()
            
            #-- reboot the modem----------------------------------------
            if cmd.reboot == True:
                mdm.heartbeat = 0
                reboot = True
                clear_modem_data()
                logger.info("Starting to reboot")
                client.device.set_control(ControlModeEnum.REBOOT)
                client = None
                connection = None
                mdm.status = "Starting to reboot"
                cmd.reboot = False
                elapsed_time = time.time() - modem_loop_start
                continue
                
            # ping to see if modem is alive-------------------------
            host = ping(mdm.modem_ip, count=1, interval=1, privileged=False)
            if not host.is_alive:
                mdm.heartbeat = 0
                mdm.status = 'Modem offline, not replying to ping'
                connection = None
                client = None
                clear_modem_data()
                elapsed_time = time.time() - modem_loop_start
                if reboot:
                    logger.info('Modem offline, no ping(rebooting)')
                    mdm.status = 'Modem offline, no ping(rebooting)'
                else:
                    logger.info('Modem offline, not replying to ping')
                continue                
                                    
            #-- sign in ------------------------------------------------
            if not connection:
                # don't query modem immediately after it comes online---
                time.sleep(10)
                mdm.heartbeat = 0

                url = F"http://{mdm.user}:{mdm.password}@{mdm.modem_ip}"
                connection = AuthorizedConnection(url)
                if  not connection:
                    mdm.status = 'Not logged in to modem'
                    elapsed_time = time.time() - modem_loop_start
                    logger.info('Not logged in to modem')
                    continue
                else:
                    logger.info("Logged in to modem")
            
            if not client:            
                mdm.heartbeat = 0
                client = Client(connection)
                if not client:
                    mdm.status = 'No client connection to modem'
                    elapsed_time = time.time() - modem_loop_start
                    logger.info('No client connection to modem')
                    continue
                else:
                    logger.info("Client connection to modem established")
                    
            mdm.status = "Connected to modem"
            #logger.info("Connected to modem")

            try:
                # get modem data ----
                try:
                    mdm.heartbeat = 0
                    time.sleep(0.1)
                    traffic    = client.monitoring.traffic_statistics()
                    sig        = client.device.signal()
                    basic      = client.device.basic_information()
                    status     = client.monitoring.status()
                    statistics = client.monitoring.month_statistics()
                    deviceinfo = client.system.deviceinfo()
                    #logger.info("Gathered modem data")
                    
                except  Exception as e:
                    dprint(F"Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",2)
                    logger.info("Modem not replying to data request")
                    mdm.status = 'Modem not replying to data request'
                    # force new login ----
                    connection = None
                    client = None
                    elapsed_time = time.time() - modem_loop_start
                    continue
                else:
                    mdm.status = 'Modem online'
                
                # pause display while data is updated ------------------
                mdm.heartbeat = 0
                display_data_event.clear() 
                
                mdm.download = int(traffic['CurrentDownloadRate'])*8//(1024*1024)
                mdm.upload = int(traffic['CurrentUploadRate'])*8//(1024*1024)

                mdm.device_name = basic['devicename']

                if mdm.generation == 5:
                    rsrp = sig["nrrsrp"]
                    rsrq = sig["nrrsrq"]
                    sinr = sig["nrsinr"]

                    txpower = sig["nrtxpower"]
                    ulfreq  = sig["nrulfreq"]
                    dlfreq  = sig["nrdlfreq"]
                    
                elif mdm.generation == 4:
                    rsrp = sig["rsrp"]
                    rsrq = sig["rsrq"]
                    sinr = sig["sinr"]

                    txpower = sig["txpower"]
                    ulfreq  = sig["lteulfreq"]
                    dlfreq  = sig["ltedlfreq"]

                mdm.plmn = sig["plmn"]
                if mdm.plmn == None or mdm.plmn == '' or mdm.plmn == ' ':
                    mdm.plmn = '0'
                mdm.cell_id = sig["cell_id"]
                
                if rsrp == None:
                    mdm.rsrp = stg.rsrp_min
                else:
                    try:
                        mdm.rsrp = int(rsrp[:-3])
                    except Exception as e :
                        mdm.rsrp = stg.rsrp_min
                        mdm.status = "RSRP Error:" + rsrp
                    if mdm.rsrp < stg.rsrp_min:
                        mdm.rsrp = stg.rsrp_min
                        
                if rsrq == None:
                    mdm.rsrq = stg.rsrq_min
                else:
                    try:
                        mdm.rsrq = float(rsrq[:-2])
                        if mdm.rsrq < stg.rsrq_min:
                            mdm.rsrq = stg.rsrq_min
                    except Exception as e:
                        mdm.rsrq = stg.rsrq_min
                        
                if sinr == None:
                    mdm.sinr = 0
                else:
                    mdm.sinr = int(sinr[:-2])
                    
                if txpower == None:
                    mdm.tx_power = "00000"
                else:
                    mdm.tx_power = txpower
                    
                if ulfreq == None:
                    mdm.ul_freq = "00000"
                else:
                    mdm.ul_freq = ulfreq
                    
                if dlfreq == None:
                    mdm.dl_freq = "00000"
                else:
                    mdm.dl_freq = dlfreq
                    
                if mdm.plmn == None:
                    mdm.plmn = "00000"
                    
                if mdm.cell_id == None:
                    mdm.cell_id = "00000"
                
                mdm.bars = int(status["SignalIconNr"])
                
                mdm.data_used = int((int(statistics["CurrentMonthDownload"]) + int(statistics["CurrentMonthUpload"])) / (1024*1024*1024))
                mdm.today_used = int((int(statistics["CurrentDayUsed"])) / (1024*1024))           
                mdm.up_time = deviceinfo['UpTime']               

                #-- release display_screen() to display the new data----
                display_data_event.set()
                #process_keyboard_commands()
                
                elapsed_time = time.time() - modem_loop_start
                
                mdm.heartbeat = 1

            except  Exception as e:
                dprint(F"Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",3)
'''
#-----------------------------------------------------------------------
# modem scan loop
#-----------------------------------------------------------------------

def monitor_modem():
        cycle = 0
        modem_reboot = False
        
        global cmd
        global mdm
        global client
        global display_data_event
        global heartbeat_event
        client = None
        connection = None

        bar  = "                                                                                                                                                                                      "
        dash = "----------------------------------------------------------------------------------------------------------"
        elapsed_time = 1.0
        heartbeat_event.set()
        
        while not cmd.stop:
            if elapsed_time < mdm.interval:
                time.sleep(mdm.interval - elapsed_time)
                
            modem_loop_start = time.time()
            display_data_event.set()
            
            #-- reboot the modem----------------------------------------
            if cmd.reboot == True:
                modem_reboot = True
                clear_modem_data()
                logger.info("Starting to reboot")
                client.device.set_control(ControlModeEnum.REBOOT)
                connection.close()
                client = None
                connection = None
                mdm.status = "Starting to reboot"
                cmd.reboot = False
                elapsed_time = time.time() - modem_loop_start
                continue
                
            # ping to see if modem is alive-------------------------
            host = ping(mdm.modem_ip, count=1, interval=1, privileged=False)
            if not host.is_alive:
                mdm.status = 'Modem offline, not replying to ping'
                connection = None
                client = None
                clear_modem_data()
                
                if modem_reboot:
                    logger.info('Modem offline, no ping(rebooting)')
                    mdm.status = 'Modem offline, no ping(rebooting)'
                else:
                    logger.info('Modem offline, not replying to ping')
                elapsed_time = time.time() - modem_loop_start
                continue                
                                    
            #-- sign in ------------------------------------------------
            if not connection:
                # don't query modem immediately after it comes online---
                if modem_reboot:
                    time.sleep(stg.restart_delay)

                url = F"http://{mdm.user}:{mdm.password}@{mdm.modem_ip}"
                try:
                    connection = AuthorizedConnection(url)
                except:
                    mdm.status = "Already logged in"
                if  not connection:
                    mdm.status = 'Not logged in to modem'
                    logger.info('Not logged in to modem')
                    elapsed_time = time.time() - modem_loop_start
                    continue
                else:
                    logger.info("Logged in to modem")
                    modem_reboot = False
            
            if not client:            
                mdm.heartbeat = 0
                client = Client(connection)
                if not client:
                    mdm.status = 'No client connection to modem'
                    logger.info('No client connection to modem')
                    elapsed_time = time.time() - modem_loop_start
                    continue
                else:
                    logger.info("Client connection to modem established")
                    
            mdm.status = "Connected to modem"

            try:
                # get modem data ----
                heartbeat_event.clear()
                if not modem_reboot:
                    try:
                        time.sleep(0.1)
                        traffic    = client.monitoring.traffic_statistics()
                        sig        = client.device.signal()
                        basic      = client.device.basic_information()
                        status     = client.monitoring.status()
                        statistics = client.monitoring.month_statistics()
                        deviceinfo = client.system.deviceinfo()
                        if cmd.test:
                            clear_modem_data()
                            mdm.status = 'Modem test halt'
                            logger.info('Test halt')
                            cmd.test = False
                            time.sleep(mdm.interval + stg.test_time)
                            logger.info('Test halt ended')
                        
                    except  Exception as e:
                        dprint(F"(2) Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",2)
                        logger.info("Modem not replying to data request")
                        mdm.status = 'Modem not replying to data request'
                        # force new login ----
                        connection = None
                        client = None
                        elapsed_time = time.time() - modem_loop_start
                        continue
                    else:
                        mdm.status = 'Modem online'
                
                # pause display while data is updated ------------------
                display_data_event.clear() 
                heartbeat_event.set()
                
                mdm.download = int(traffic['CurrentDownloadRate'])*8//(1024*1024)
                mdm.upload = int(traffic['CurrentUploadRate'])*8//(1024*1024)

                mdm.device_name = basic['devicename']

                if mdm.generation == 5:
                    rsrp = sig["nrrsrp"]
                    rsrq = sig["nrrsrq"]
                    sinr = sig["nrsinr"]

                    txpower = sig["nrtxpower"]
                    ulfreq  = sig["nrulfreq"]
                    dlfreq  = sig["nrdlfreq"]
                    
                elif mdm.generation == 4:
                    rsrp = sig["rsrp"]
                    rsrq = sig["rsrq"]
                    sinr = sig["sinr"]

                    txpower = sig["txpower"]
                    ulfreq  = sig["lteulfreq"]
                    dlfreq  = sig["ltedlfreq"]

                mdm.plmn = sig["plmn"]
                if mdm.plmn == None or mdm.plmn == '' or mdm.plmn == ' ':
                    mdm.plmn = '0'
                mdm.cell_id = sig["cell_id"]
                
                if rsrp == None:
                    mdm.rsrp = stg.rsrp_min
                else:
                    try:
                        mdm.rsrp = int(rsrp[:-3])
                    except Exception as e :
                        mdm.rsrp = stg.rsrp_min
                        mdm.status = "RSRP Error:" + rsrp
                    if mdm.rsrp < stg.rsrp_min:
                        mdm.rsrp = stg.rsrp_min
                        
                if rsrq == None:
                    mdm.rsrq = stg.rsrq_min
                else:
                    try:
                        mdm.rsrq = float(rsrq[:-2])
                        if mdm.rsrq < stg.rsrq_min:
                            mdm.rsrq = stg.rsrq_min
                    except Exception as e:
                        mdm.rsrq = stg.rsrq_min
                        
                if sinr == None:
                    mdm.sinr = 0
                else:
                    mdm.sinr = int(sinr[:-2])
                    
                if txpower == None:
                    mdm.tx_power = "00000"
                else:
                    mdm.tx_power = txpower
                    
                if ulfreq == None:
                    mdm.ul_freq = "00000"
                else:
                    mdm.ul_freq = ulfreq
                    
                if dlfreq == None:
                    mdm.dl_freq = "00000"
                else:
                    mdm.dl_freq = dlfreq
                    
                if mdm.plmn == None:
                    mdm.plmn = "00000"
                    
                if mdm.cell_id == None:
                    mdm.cell_id = "00000"
                
                mdm.bars = int(status["SignalIconNr"])
                
                mdm.data_used = int((int(statistics["CurrentMonthDownload"]) + int(statistics["CurrentMonthUpload"])) / (1024*1024*1024))
                mdm.today_used = int((int(statistics["CurrentDayUsed"])) / (1024*1024))           
                mdm.up_time = deviceinfo['UpTime']               

                #process_keyboard_commands()               
                #-- release display_screen() to display the new data----
                display_data_event.set()
                
                elapsed_time = time.time() - modem_loop_start
                
            except  Exception as e:
                dprint(F"(3) Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",2)
                
        if connection:
            connection.close()
            logger.info("connection closed")
        else:
            logger.info("no connection to close")


#-----------------------------------------------------------------------
# Display loop
#-----------------------------------------------------------------------

class DisplayData(Thread) :
    def __init__(self) :
        Thread.__init__(self)
    def run(self):

        cycle = 0
        
        global cmd
        global mdm

        bar  = "                                                                                                                                                                                      "
        dash = "----------------------------------------------------------------------------------------------------------"
        try:
            clear_modem_data()
        except:
            pass
       
        while not cmd.stop:
            try:
                display_data_event.wait(1.2) # wait until data is stable ---
                display_start_time = time.time()
                if not cmd.pause:
                    try:
                        # Date
                        date = time.strftime('%d %B %Y - %H:%M:%S',time.localtime())
                        # Draw the screen ---
                        y = 1                  
                        stdscr.erase()
                        
                        # Title ---
                        stdscr.addstr(y, 1, date + " - Huawei " + basename(sys.argv[0]) + "  " + mdm.device_name , curses.color_pair(1)|curses.A_STANDOUT|curses.A_REVERSE)
                        y += 1
                        
                        # Moving title bar ---
                        dash2 = dash[0:(cycle % 68)] + '#' + dash[0:67-(cycle % 68):]
                        stdscr.addstr(y, 1, dash2, curses.color_pair(1)) 
                        y += 1
                        stdscr.addstr(y, 1, "Up time(h:m:s)", curses.color_pair(1))
                        try:
                            minutes, seconds = divmod(mdm.up_time, 60)
                            hours, minutes   = divmod(minutes,60)
                        except:
                            minutes = 0
                            seconds = 0
                            hours = 0
                        
                        stdscr.addstr(y, 16, F"{hours}:{minutes}:{seconds}", curses.color_pair(1)|curses.A_BOLD)
                        stdscr.addstr(y, 30, F"Modem address: {mdm.modem_ip}")
                        
                        # Ping times ---
                        y += 1
                        stdscr.addstr(y, 1, 'Ping :         ')
                        if png.time == -2 :
                            stdscr.addstr(y, 16, "KO", curses.color_pair(2))
                        elif png.time== -1 :
                            stdscr.addstr(y, 16, "0", curses.color_pair(1))             
                        else :
                            stdscr.addstr(y, 16, F"{png.time}", curses.color_pair(1)|curses.A_BOLD)
                            stdscr.addstr(y, 20, ' ms')
                        stdscr.addstr(y, 30, F"Ping address:  {png.ping_ip}")
                       
                        y += 1
                        
                        # Strength bar ---------------------------------------------
                        stdscr.addstr(y, 1, "Bars :         "+str(mdm.bars))
                        stdscr.addstr(y, 16, F"{mdm.bars}", curses.color_pair(1)|curses.A_BOLD)
                        stdscr.addstr(y, 25, dash[0 : mdm.bars], curses.color_pair(mdm.bars)|curses.A_BOLD)          
                        
                        # RSRP bar -------------------------------------------------
                        y += 1
                        stdscr.addstr(y, 1, "RSRP :         ", curses.color_pair(1))
                        stdscr.addstr(y, 16, F"{mdm.rsrp}", curses.color_pair(1)|curses.A_BOLD)
                        stdscr.addstr(y, 21, 'dBm', curses.color_pair(1))
                        if mdm.rsrp >= -80:
                            bar_colour = 5 
                        elif mdm.rsrp >= -90:
                            bar_colour = 4
                        elif mdm.rsrp >= -100:
                            bar_colour = 3
                        else:
                            bar_colour = 2
                        stdscr.addstr(y, 25, bar[0 : mdm.rsrp - stg.rsrp_min], curses.color_pair(bar_colour)|curses.A_BOLD)
                        
                        
                        stdscr.addstr(y, 25 + mdm.rsrp - stg.rsrp_min, dash[0:81 - mdm.rsrp + stg.rsrp_min] + '|', curses.color_pair(1))
                        stdscr.addstr(y, 108, '[-60 dBm]', curses.color_pair(1))
                        
                        # RSRQ bar -------------------------------------------------
                        y += 1
                        stdscr.addstr(y, 1, "RSRQ :         ", curses.color_pair(1))
                        stdscr.addstr(y, 16, F"{mdm.rsrq}", curses.color_pair(1)|curses.A_BOLD)
                        stdscr.addstr(y, 21, "dB", curses.color_pair(1))
                        
                        if mdm.rsrq >= -10:
                            bar_colour = 5 
                        elif mdm.rsrq >= -15:
                            bar_colour = 4
                        elif mdm.rsrq >= -20:
                            bar_colour = 3
                        else:
                            bar_colour = 2    

                        stdscr.addstr(y, 25, bar[0 : int(mdm.rsrq - stg.rsrq_min)], curses.color_pair(bar_colour)|curses.A_BOLD)
                        stdscr.addstr(y, 25+int(mdm.rsrq - stg.rsrq_min), dash[0:30 - int(mdm.rsrq - stg.rsrq_min)] + '|', curses.color_pair(1))
                        stdscr.addstr(y, 108, '[-5.0 dB]', curses.color_pair(1))
                        
                        # SINR bar--------------------------------------------------
                        y += 1
                        if mdm.sinr >= 20:
                            bar_colour = 5 
                        elif mdm.sinr >= 13:
                            bar_colour = 4
                        elif mdm.sinr >= 0:
                            bar_colour = 3
                        else:
                            bar_colour = 2

                        stdscr.addstr(y, 1, "SINR :         ", curses.color_pair(1))
                        stdscr.addstr(y, 16, F"{mdm.sinr}", curses.color_pair(1)|curses.A_BOLD)
                        stdscr.addstr(y, 21, "dB", curses.color_pair(1))
                        stdscr.addstr(y, 25, bar[0 : mdm.sinr] , curses.color_pair(bar_colour)|curses.A_BOLD)
                        stdscr.addstr(y, 25+mdm.sinr, dash[0:25 - mdm.sinr] + '|', curses.color_pair(1))
                        stdscr.addstr(y, 108, '[25.0 dB]', curses.color_pair(1))
                        
                        # other data -----------------------------------------------
                        y += 2
                        stdscr.addstr(y, 1, "txpower :      " + mdm.tx_power, curses.color_pair(1))
                        y += 1
                        stdscr.addstr(y, 1, "ulfreq :       ", curses.color_pair(1))
                        try:
                            stdscr.addstr(y, 16, F"{float(mdm.ul_freq[:4])/1000}", curses.color_pair(1)|curses.A_BOLD)
                        except:
                            pass
                        stdscr.addstr(y, 20, ' GHz', curses.color_pair(1))
                        y += 1
                        stdscr.addstr(y, 1, "dlfreq :       " , curses.color_pair(1))
                        try:
                            stdscr.addstr(y, 16, F"{float(mdm.dl_freq[:4])/1000}", curses.color_pair(1)|curses.A_BOLD)
                        except:
                            pass
                        stdscr.addstr(y, 20, ' GHz', curses.color_pair(1))
                        y += 1
                        
                        stdscr.addstr(y, 1, "CELL ID :      ", curses.color_pair(1)) 
                        stdscr.addstr(y, 16, mdm.cell_id[10:], curses.color_pair(1)|curses.A_BOLD)           
                        y += 1
                        stdscr.addstr(y, 1, "PLMN :         ", curses.color_pair(1))
                        stdscr.addstr(y, 16, mdm.plmn, curses.color_pair(1)|curses.A_BOLD) 
                        try:
                             plmn_value = plmn.plmn_dict[int(mdm.plmn)]
                        except:
                            plmn_value = '----'
                        stdscr.addstr(y, 25, plmn_value, curses.color_pair(1)|curses.A_BOLD)
                        y += 2
                        stdscr.addstr(y, 1, "Download :     " + str(mdm.download) + '  ', curses.color_pair(1))
                        stdscr.addstr(y, 16, F"{mdm.download} ", curses.color_pair(1)|curses.A_BOLD)
                        stdscr.addstr(y, 20, " Mbit/s", curses.color_pair(1))
                        stdscr.addstr(y, 28, dash[0 : mdm.download % 100], curses.color_pair(2)|curses.A_BOLD)
                        y += 1
                        stdscr.addstr(y, 1, "Upload :       ", curses.color_pair(1))
                        stdscr.addstr(y, 16, F"{mdm.upload} ", curses.color_pair(1)|curses.A_BOLD)
                        stdscr.addstr(y, 20, " Mbit/s", curses.color_pair(1))
                        stdscr.addstr(y, 28, dash[0 : mdm.upload % 100], curses.color_pair(3)|curses.A_BOLD) 
                        y += 2

                        stdscr.addstr(y, 1, "Month used :   " + str(mdm.data_used), curses.color_pair(1))
                        stdscr.addstr(y, 16, F"{mdm.data_used}", curses.color_pair(1)|curses.A_BOLD)
                        stdscr.addstr(y, 20, " Gbyte", curses.color_pair(1))
                        y += 1
                        stdscr.addstr(y, 1, "Today used :   ", curses.color_pair(1))
                        stdscr.addstr(y, 16, F"{mdm.today_used}", curses.color_pair(1)|curses.A_BOLD)
                        stdscr.addstr(y, 20, " Mbyte", curses.color_pair(1))
                            
                        y += 2
                        
                        # colour key --- 
                        stdscr.addstr(y, 1,  "     ", curses.color_pair(5)|curses.A_BOLD)
                        stdscr.addstr(y, 6,  ":Excellent", curses.color_pair(1))
                        
                        stdscr.addstr(y, 18, "     ", curses.color_pair(4)|curses.A_BOLD)
                        stdscr.addstr(y, 23, ":Good", curses.color_pair(1))
                        
                        stdscr.addstr(y, 30, "     ", curses.color_pair(3)|curses.A_BOLD)
                        stdscr.addstr(y, 35, ":Adequate(mid-cell)", curses.color_pair(1))
                        
                        stdscr.addstr(y, 56, "     ", curses.color_pair(2)|curses.A_BOLD)
                        stdscr.addstr(y, 61, ":Poor(edge-cell)", curses.color_pair(1))
                        
                        y += 1
                        stdscr.addstr(y, 1,  "RSRP = Reference Signal Receive Power, RSRQ = Reference Signal Receive Quality", curses.color_pair(1))
                        y += 1
                        stdscr.addstr(y, 1,  "Commands q:quit, r:reboot modem, d:dump all modem data,\n m:modem log, s:signal log, a:about, h:help", curses.color_pair(1)|curses.A_BOLD)
                        y += 2
                        stdscr.addstr(y, 1,  F"Status: {mdm.status}", curses.color_pair(1))
                        y += 1
                        stdscr.addstr(y, 1,  dash2, curses.color_pair(1))
                        stdscr.refresh()
                    except:
                        stdscr.refresh()
                        pass
                
                try:
                    plmn_value = plmn.plmn_dict[int(mdm.plmn)]
                except:
                    plmn_value = "----"
                log_str1 = F"{mdm.plmn} {plmn_value} {mdm.cell_id[10:]} {mdm.bars} bars "
                log_str2 = F"{png.time:6.1f} ms {mdm.rsrp} dBm {mdm.rsrq} dB {mdm.sinr} dB {mdm.today_used:6d} Mbyte {mdm.download:4d} Mbit/s"
                logger.info(log_str1 + log_str2)
                
                cycle += 1
                #process_keyboard_commands()
                display_finish_time = time.time()
                diff = display_finish_time - display_start_time
                if diff < mdm.interval - 0.001:
                    time.sleep(mdm.interval - 0.001 - diff)  
            except  Exception as e:
                dprint(F"(4) Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",2)

#-----------------------------------------------------------------------

def process_keyboard_commands():
    
    global cmd
    global stdscr
    
    #-- show modem data ------------------------------------------------
    if cmd.show_modem_data:
        cmd.show_modem_data = False
        dump_data()
        if platform.system() == 'Linux':
            #subprocess.Popen([F'{stg.terminal}', F'{stg.x_flag}', './modem-data.sh'])
            cmd.pause = True
            subprocess.run(['./slit','modem-data.txt'])
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()
        elif platform.system() == 'Windows':
            cmd.pause = True
            subprocess.call('.\slit.exe modem-data.txt')
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()
    
    #-- show modem log -------------------------------------------------
    if cmd.show_modem_log:
        cmd.show_modem_log = False
        log_string = client.log.loginfo()['LogContent']
        x = log_string.replace("\\r\\n", chr(10))
        log_file = open("modem-log.txt", "w")
        log_file.write(x)
        log_file.close()
        
        if platform.system() == 'Linux':
            #subprocess.Popen([F'{stg.terminal}', F'{stg.x_flag}','./modem-log.sh'])
            cmd.pause = True
            subprocess.run(['./slit','modem-log.txt'])
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()
        elif platform.system() == 'Windows':
            cmd.pause = True
            subprocess.call('.\slit.exe modem-log.txt')
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()
    
    #-- show signal log ------------------------------------------------    
    if cmd.show_signal_log:
        cmd.show_signal_log = False
        if platform.system() == 'Linux':
            cmd.pause = True
            subprocess.run(['./slit','-f','signal-log.txt'])
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()
            #subprocess.Popen([F'{stg.terminal}', F'{stg.x_flag}','./signal-log.sh'])
        elif platform.system() == 'Windows':
            cmd.pause = True
            subprocess.call('.\slit.exe -f signal-log.txt')
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()
    
    #-- show about file ------------------------------------------------    
    if cmd.show_about:
        cmd.show_about = False
        if platform.system() == 'Linux':
            cmd.pause = True
            subprocess.run(['./slit','README.md'])
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()
        elif platform.system() == 'Windows':
            cmd.pause = True
            subprocess.call('.\slit.exe README.md')
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()
    
    #-- show help file -------------------------------------------------    
    if cmd.show_help:
        cmd.show_help = False
        if platform.system() == 'Linux':
            #subprocess.Popen([F'{stg.terminal}', F'{stg.x_flag}', './help.sh'])
            cmd.pause = True
            subprocess.run(['./slit','help.txt'])
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()
        elif platform.system() == 'Windows':
            cmd.pause = True
            subprocess.call('.\slit.exe help.txt')
            cmd.pause = False
            #stdscr.noutrefresh()
            stdscr.clear()

#-----------------------------------------------------------------------


def dprint(var, act):

    if act==0:
        return
    
    if stg.debug:
        if act == 1:
            print(var)
        elif act == 2:
            logger.info(var)
        elif act == 3:
            print(var)
            logger.info(var)
        else:
            return
    return
    
#-----------------------------------------------------------------------

def clear_modem_data():
    global mdm
    global client

    mdm.tx_power    = ''
    mdm.ul_freq     = '0000'
    mdm.dl_freq     = '0000'
    mdm.plmn        = '0'
    mdm.cell_id     = ''
    mdm.sinr        = 0
    mdm.bars        = 0
    mdm.data_used   = 0
    mdm.today_used  = 0
    mdm.download    = 0
    mdm.upload      = 0
    mdm.up_time     = '0'
    mdm.rsrp        = stg.rsrp_min
    mdm.rsrq        = stg.rsrq_min
    ping_time       = 0

#-----------------------------------------------------------------------

def initialize_curses():
    global curses
    global win
    global stdscr
    try:
        stdscr = curses.initscr()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_YELLOW)
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_GREEN)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(True) 
        curses.curs_set(0)
        title = "5G Top"

        stdscr.scrollok(1)
        stdscr.idlok(1)
    except  Exception as e:
        dprint(F"(5) Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",2)
        
#-----------------------------------------------------------------------

def cleanup_curses():
    global curses
    global win
    global stdscr
    global cmd
    
    try:
        curses.nocbreak()
        stdscr.keypad(False)
        curses.echo()
        curses.endwin()
        cmd.stop = True
        logger.info("Program terminated...")
        os.system('clear')
        print("5gtop has ended")
    except:
        pass

#-----------------------------------------------------------------------

def signal_handler(sig, frame):
    cmd.stop = True
    cleanup_curses()
    sys.exit(0)
    
#-----------------------------------------------------------------------
# Main program
#-----------------------------------------------------------------------

# Global variables


cmd = Settings()

cmd.stop            = False
cmd.pause           = False
cmd.reboot          = False
cmd.show_modem_data = False
cmd.show_help       = False
cmd.show_modem_log  = False
cmd.show_signal_log = False
cmd.kill            = False
cmd.test            = False
cmd.show_about      = False

png = Settings()    

png.ping_ip  = ''
png.interval = ''
png.time     = 0

mdm = Settings()

mdm.device_name = ''
mdm.tx_power    = ''
mdm.ul_freq     = ''
mdm.dl_freq     = ''
mdm.plmn        = ''
mdm.cell_id     = ''
mdm.rsrp        = stg.rsrp_min 
mdm.rsrq        = stg.rsrq_min
mdm.sinr        = 0
mdm.bars        = 0
mdm.data_used   = 0
mdm.today_used  = 0
mdm.download    = 0
mdm.upload      = 0
mdm.up_time     = ''
mdm.status      = ''
mdm.interval    = 1
mdm.generation  = 5
mdm.password    = ''
mdm.modem_ip    = ''
mdm.modem_id    = 0
mdm.heartbeat   = 0
mdm.user        = stg.user

locale.setlocale(locale.LC_ALL, '') # sets locale to user default settings

#--Parse command line arguments-----------------------------------------

parser = ArgumentParser(description="5gtop: monitor signal of 4G/5G Huawei modems")
parser.add_argument('-m', '--modemip',    type=str, required=True,  help = "the IP address of the 5G modem(required)")
parser.add_argument('-w', '--password',   type=str, required=True,  help = "admin password of the 5G modem(required)")
parser.add_argument('-p', '--pingip',     type=str, required=False, help = "IP address of host to be pinged(optional)")
parser.add_argument('-i', '--interval',   type=int, required=False, help = "measurement interval in seconds, default is one second(optional)")
parser.add_argument('-g', '--generation', type=int, required=False, help = "4 for 4G or 5 for 5G(optional, defaults to 5)")
parser.add_argument('-a', '--about',      action='store_true', required=False, help = "About 5gtop(optional)")
parser.add_argument('-u', '--user',       type=str, required=False, help = F"Admin user name for modem, (optional, defaults to '{stg.user}')")
args = parser.parse_args()

atexit.register(cleanup_curses)
signal.signal(signal.SIGINT, signal_handler)

mdm.modem_ip = args.modemip
mdm.password = args.password

if args.user:
    mdm.user = args.user
else:
    mdm.user = stg.user

if args.about:
    if platform.system() == 'Linux':
        subprocess.Popen([F'{stg.terminal}',F'{stg.x_flag}','./about.sh'])
    elif platform.system() == 'Windows':
        subprocess.Popen(['less.exe', 'about.txt'])
    sys.exit()

if args.generation:
    mdm.generation = args.generation
    if mdm.generation != 4 and mdm.generation != 5:
        print(F"You have specified an incorrect generation - '{mdm.generation}' is invalid, allowed are '4' or '5")
        sys.exit()
else:
    mdm.generation = 5

if not args.interval:
    png.interval      = 1.0
    mdm.interval      = 1.0
else:
    png.interval      = args.interval
    mdm.interval      = args.interval
    if args.interval < 1.0:
        png.interval  = 1.0
        mdm.interval  = 1.0


#--Check for properly formatted ping address----------------------------

if args.pingip :
    try:
        ping_ip = ipaddress.ip_address(args.pingip)
        png.ping_ip = ping_ip.exploded
    except ValueError:
        print(F'address/netmask is invalid: {args.pingip}')
        sys.exit(1)
    except:
        print(F'Usage : --pingip 41.73.51.11, you entered {args.pingip}')
        sys.exit(2)
else:
    png.ping_ip = 0
    
#--Check for properly formatted modem address---------------------------

try:
    modem_ip = ipaddress.ip_address(args.modemip)
    mdm.modem_ip = modem_ip.exploded
except ValueError:
    print(F'address/netmask is invalid: {args.modemip}')
    sys.exit(1)
except:
    print(F'Usage : --modemip 192.168.8.1, you entered {args.modemip}')
    sys.exit(2)


#-- Check the modem address and ping the modem--------------------------

try :
    for i in range(6):
        host = ping(mdm.modem_ip, count=1, interval=1, privileged=False)
        if host.is_alive:
            ping_time = host.avg_rtt
            break
        else:
            ping_time = -1
except  Exception as e:
    dprint(F"(6) Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",3)
    print(F"The modem is not replying or the modem address is incorrect {mdm.modem_ip}")
    sys.exit()
    
if ping_time < 0:
    print(F"{mdm.generation}G Modem not available. Correct address? Is it online? {mdm.modem_ip}")
    sys.exit()

try:
    # initialize events-------------------------------------------------
    display_data_event = threading.Event()
    heartbeat_event    = threading.Event()
    
    #initial conditions ----
    display_data_event.clear()
    heartbeat_event.clear()
   
    #-- Initialize the threads------------------------------------------
    keyboard_thread  = Keyboard() 
    ping_thread      = Ping(1)
    modem_thread     = KThread(target=monitor_modem)
    display_thread   = DisplayData()
    heartbeat_thread = ModemHeartbeat()
    
    #-- Name the threads -----------------------------------------------
    keyboard_thread.name  = 'Keyboard'
    ping_thread.name      = 'Ping'
    modem_thread.name     = 'Modem'
    display_thread.name   = 'Display'
    heartbeat_thread.name = 'Heartbeat'

    #-- Initialize curses ----------------------------------------------
    initialize_curses()

    #-- Threads start---------------------------------------------------
    mdm.status = "Connecting to modem"
    display_thread.start()
    keyboard_thread.start() 
    ping_thread.start()
    modem_thread.start()
    heartbeat_thread.start()
    
    #-- report all thread names and PID --------------------------------
    for thread in threading.enumerate():
        thread_name =thread.name
        thread_ident=thread.native_id
        logger.info(F"{thread_name}, {thread_ident}")
        if thread_name == 'Modem':
            mdm.modem_id = thread_ident
    
    # 'q' will send a 'stop' command to all threads
    # ctrl-c will terminate the program

    if keyboard_thread.is_alive():
        logger.info("keyboard_thread.join()")
        
        #-- wait here for the quit command -----------------------------
        keyboard_thread.join() 
        
        #-- Clean up and end 5gtop -------------------------------------
        logger.info("Quitting 5gtop")
        cleanup_curses()
        os.system('clear')
        print('5gtop has ended')
        sys.exit(0)        
        os.kill(mdm.modem_id, signal.SIGKILL)

    else:
        cleanup_curses()
        print("Program startup failed") 
        logger.info("Program startup failed") 
        os.kill(mdm.modem_id, signal.SIGKILL)   

except  Exception as e:
    cmd.stop = True
    dprint(F"(7) Error on line {format(sys.exc_info()[-1].tb_lineno)}, {type(e).__name__}, {e}",2)


#=======================================================================
