#!/usr/bin/python2
# -*- coding: utf-8 -*-

from scapy.all import *
from geoip import geolite2
from terminaltables import AsciiTable
from twilio.rest import TwilioRestClient
from bs4 import BeautifulSoup as bsp
import os
import sys
import json
import cmd
import commands
import getpass
import random
import time
import smtplib
import paramiko
import shodan
import requests

#Color
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
LR = '\033[1;31m' # light red
LG = '\033[1;32m' # light green
LO = '\033[1;33m' # light orange
LB = '\033[1;34m' # light blue
LP = '\033[1;35m' # light purple
LC = '\033[1;36m' # light cyan

recon_modules = ['shodan', 'iplocate', 'hostseek', 'domaininfo']
networking_modules = ['bruteforce']
http_modules = ['mitm', 'webcrawler']
smtp_modules = ['smsbomb', 'emailbomb', 'emailmining']
mail_providers = ['smtp.gmail.com', 'smtp-mail.outlook.com', 'smtp.mail.yahoo.com', 'smtp.mail.att.net', 'smtp.comcast.net', 'smtp.verizon.net']
wifi_modules = ['wificracking', 'wifiscanning']


def help_menu():
	print LB + "+============================================+" + W
	print LB + "|  Jarvis Mobile Security Framework Menu     |" + W
	print LB + "+============================================+" + W
	print LB + "|               [COMMANDS]                   |" + W
	print LB + "| help: Help menu                            |" + W
	print LB + "| exit: Exit script                          |" + W
	print LB + "| clear: Clear terminal                      |" + W
	print LB + "+============================================+" + W

def recon_menu():
	print LB + "+============================================+" + W
	print LB + "|               Recon menu                   |" + W
	print LB + "+============================================+" + W
	print LB + "| list: List recon modules                   |" + W
	print LB + "| use: Use recon module                      |" + W
	print LB + "| clear: Clear shell                         |" + W
	print LB + "| back: Go back to main interpreter          |" + W
	print LB + "| help: This menu                            |" + W
	print LB + "+============================================+" + W
	
def http_menu():
	print LB + "+============================================+" + W
	print LB + "|                Http menu                   |" + W
	print LB + "+============================================+" + W
	print LB + "| list: List http modules                    |" + W
	print LB + "| use: Use http module                       |" + W
	print LB + "| clear: Clear shell                         |" + W
	print LB + "| back: Go back to main interpreter          |" + W
	print LB + "| help: This menu                            |" + W
	print LB + "+============================================+" + W

def smtp_menu():
	print LB + "+============================================+" + W
	print LB + "|                Smtp menu                   |" + W
	print LB + "+============================================+" + W
	print LB + "| list: List smtp modules                    |" + W
	print LB + "| use: Use smtp module                       |" + W
	print LB + "| clear: Clear shell                         |" + W
	print LB + "| back: Go back to main interpreter          |" + W
	print LB + "| help: This menu                            |" + W
	print LB + "+============================================+" + W

def networking_menu():
	print LB + "+============================================+" + W
	print LB + "|                Networking menu             |" + W
	print LB + "+============================================+" + W
	print LB + "| info: Network info (yours)                 |" + W
	print LB + "| list: List networking modules              |" + W
	print LB + "| use: Use networking module                 |" + W
	print LB + "| clear: Clear shell                         |" + W
	print LB + "| back: Go back to main interpreter          |" + W
	print LB + "| help: This menu                            |" + W
	print LB + "+============================================+" + W

def wifi_menu():
	print LB + "+============================================+" + W
	print LB + "|                 Wifi menu                  |" + W
	print LB + "+============================================+" + W
	print LB + "| list: List wifi modules                    |" + W
	print LB + "| use: Use wifi module                       |" + W
	print LB + "| clear: Clear shell                         |" + W
	print LB + "| back: Go back to main interpreter          |" + W
	print LB + "| help: This menu                            |" + W
	print LB + "+============================================+" + W

def shodan_menu():
	print LB + "+============================================+" + W
	print LB + "|                Shodan menu                 |" + W
	print LB + "+============================================+" + W
	print LB + "| 1. Search topic                            |" + W
	print LB + "| 2. Host                                    |" + W
	print LB + "| 3. Back to recon                           |" + W
	print LB + "+============================================+" + W

def main_menu():
	print G + "+============================================+" + B
	print G + "|      Jarvis Mobile Security Framework      |" + B
	print G + "|                 Start Menu                 |" + B
	print G + "+============================================+" + B
	print G + "| recon: recon part of the tool              |" + B
	print G + "| smtp: smtp part of the tool                |" + B
	print G + "| wifi: wifi part of the tool                |" + B
	print G + "| networking: networking part of the tool    |" + B
	print G + "| http: http part of the tool                |" + B
	print G + "| exit: exit the tool                        |" + B
	print G + "+============================================+" + B

def network_info():
    lanip = os.popen("ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'").read()
    public_ip = os.popen("wget http://ipinfo.io/ip -q0 -").read()
    mac_address = os.popen("cat /sys/class/net/eno1/address").read()
    gateway_ip = os.popen("/sbin/ip route | awk '/default/ { printf $3 }'").read()
    table_data = [
           ["Network Infomation", ""],
           ["Local IP Address: ", str(lanip)],
           ["Public IP Address: ", str(public_ip)],
           ["MAC Address: ", str(mac_address)],
           ["Gateway IP: ", str(gateway_ip)]
    ]
    table = AsciiTable(table_data)
    print B + table.table + W

def recon():

	class RECON_SHELL(cmd.Cmd):
		prompt = LP + '[jarvismobile/recon]:~$ ' + W
		def do_list(self, line):
			print LO + "[RECON MODULES]" + W
			for item in recon_modules:
				print B + item + W
		def do_use(self, line):
			module_name = line.strip()
			if(module_name not in recon_modules):
				print R + "[!] Not a recon module. Type 'list' to show modules." + W
			else:
				if(module_name == 'shodan'):
					API_KEY = raw_input("[>] Shodan API key: ")
					if(API_KEY == ""):
						print R + "[!] No API key given" + W
					else:
						try:
							api = shodan.Shodan(API_KEY)
						except shodan.APIError, e:
							print R + "[!] Shodan Error: %s" % e + W
							return False
						class SHODAN(cmd.Cmd):
							shodan_menu()
							prompt = LP + '[jarvismobile/recon/shodan]:~$ ' + W
							def do_1(self, line):
								search_topic = line.strip()
								try:
									results = api.search(search_topic)
									print LO + "Results found: %s" % results['total'] + W
									for result in results['matches']:
										print LG + "IP : %s" % result['ip_str'] + W
										print LG + result['data'] + W
										print ''
								except shodan.APIError, e:
									print R + "[!] Shodan Error: %s" % e + W
							def do_2(self, line):
								host_ip = line
								host = api.host(host_ip)
								# print info
								print LG + """
									IP : %s
									Organization : %s
									Operating System : %s
								""" % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')) + W
								for item in host['data']:
									print LG + """
										Port : %s
										Banner : %s
									""" % (item['port'], item['data']) + W
							def do_3(self, line):
								return -1
						SHODAN().cmdloop()
				elif(module_name == 'iplocate'):
					ip = raw_input("[>] IP: ")
					match = geolite2.lookup(ip)
					if(match is not None):
						country = match.country
						continent = match.continent
						timezone = match.timezone
						table_data = [
							['Info for: ', str(ip)],
							['Country: ',  str(country)],
							['Continent: ', str(continent)],
							['Timezone: ', str(timezone)],
						]
						table = AsciiTable(table_data)
					        print B + table.table + W
                                elif(module_name == 'hostseek'):
                                    def arp_display(pkt):
                                        if pkt[ARP].op == 1:
                                            return "Request: " + pkt[ARP].psrc + " is asking about " + pkt[ARP].pdst
                                        if pkt[ARP].op == 2:
                                            return "*Response: " + pkt[ARP].hwsrc + " has address " + pkt[ARP].psrc
                                    print sniff(prn=arp_display, filter="arp", store=0, count=100)

				else:
					print R + module_name + W
		def do_clear(self, line):
			os.system('clear')
		def do_help(self, line):
			recon_menu()
		def do_exit(self, line):
			exit(1)
		def do_EOF(self, line):
			exit(1)
		def do_back(self, line):
			os.system('clear')
			choice = random.choice(banners)
			if(choice == 'banner1'):
				banner1()
			else:
				banner2()
			main_menu()
			return -1
	RECON_SHELL().cmdloop()

def smtp():
	def sms_bomb(target, count, source, message):
		accountSID = str(raw_input("[>] Account SID: "))
		authToken = str(raw_input("[>] Auth Token: "))
		twilioCli = TwilioRestClient(accountSID, authToken)
		for i in range(count):
			message = twilioCli.messages.create(body=message, from_=source, to=target)
			print LG + "[*]" + W + B + " SMS sent to: " + W + LG + target + W
			time.sleep(5)

	def email_bomb(target, count, source, provider):
		#bomb
		if(provider not in mail_providers):
			print R + "[!] Not a mail provider or not supported" + W
		else:
			smtpObj = smtplib.SMTP_SSL(provider, 465)
			password = getpass.getpass(LG + 'Password for ' + W + LR + source + ': ' + W)
			if(password == ''):
				print R + "[!] Password is null" + W
			else:
				smtpObj.login(source, password)
				subject = raw_input(LG + "Subject for email: " + W)
				for i in range(count):
					smtpObj.sendmail(source, target, subject)
					print(LG + "[*] " + W + B + "Email sent to: " + W + LG + target + " with subject of: " + R + subject + W)
					time.sleep(3)

	class SMTP_SHELL(cmd.Cmd):
		prompt = LP + '[jarvismobile/smtp]:~$ ' + W
		def do_list(self, line):
			print LO + "[SMTP Modules]" + W
			for item in smtp_modules:
				print B + item + W
		def do_use(self, line):
			module_nme = line.strip()
			if(module_name == 'asjhas'):
				print R + "[!] Not done yet" + W
			elif(module_name == 'emailbombing'):
				print LO + "[PROVIDERS]" 	+ W
				for item in mail_providers:
					print B + item + W
				target = raw_input("[>] Target: ")
				number = int(raw_input("[>]Number of emails to be sent: "))
				source = raw_input(prompt="[>] Source: ")
				provider = raw_input("[>] Mail Providers: ")
				email_bomb(target, number, source, provider)
			elif(module_name == 'smsbombing'):
				target = raw_input("[>] Target: ")
				number = int(raw_input("[>] Number of SMS messages to be sent: "))
				source = raw_input("[>] Source: ")
				message = raw_input("[>] Message to spam: ")
				sms_bomb(target, number, source, message)
			else:
				print R + "Error" + W
		def do_clear(self, line):
			os.system("clear")
		def do_help(self, line):
			smtp_menu()
		def do_exit(self, line):
			exit(1)
		def do_EOF(self, line):
			exit(1)
		def do_back(self, line):
			os.system('clear')
			main_menu()
			return -1
	SMTP_SHELL().cmdloop()

def http():
	class HTTP_SHELL(cmd.Cmd):
		prompt = LP + '[jarvismobile/http]:~$ ' + W
		def do_list(self, line):
			print LO + "[HTTP MODULES]" + W
			for item in http_modules:
				print B + item + W
		def do_use(self, line):
			module_name = line.strip()
			if(module_name not in http_modules):
				print R + "[!] Not a http module" + W
			else:
				if(module_name == 'webcrawler'):
					site = raw_input("[>] Site to crawl: ")
					r = requests.get("http://" +(site))
					data = r.text
					soup = bs(data)
					print LO + "[LINKS FROM %s]" % site + W
					for link in soup.find_all('a'):
						print B + link.get('href') + W
		def do_clear(self, line):
			os.system("clear")
		def do_help(self, line):
			http_menu()

		def do_exit(self, line):
			exit(1)
		def do_EOF(self, line):
			exit(1)
		def do_back(self, line):
			os.system("clear")
			main_menu()
			return -1
	HTTP_SHELL().cmdloop()

def networking():
	class NETWORKING_SHELL(cmd.Cmd):
		prompt = LP + '[jarvismobile/networking]:~$ ' + W
		def do_list(self, line):
			print LO + "[NETWORKING MODULES]" + W
			for item in networking_modules:
				print B + item + W
		def do_use(self, line):
			module_name = line.strip()
		def do_info(self, line):
			network_info()
		def do_clear(self, line):
			os.system('clear')
		def do_help(self, line):
			networking_menu()
		def do_exit(self, line):
			exit(1)
		def do_back(self, line):
			os.system("clear")
			main_menu()
			return -1
	NETWORKING_SHELL().cmdloop()

def wifi():
	class WIFI_SHELL(cmd.Cmd):
		prompt = LP + '[jarvismobile/wifi]:~$ ' + W
		def do_list(self, line):
			print LO + '[WIFI MODULES]' + W
			for item in wifi_modules:
				print B + item + W
		def do_use(self, line):
			module_name = line.strip()
			print R + module_name + W
		def do_clear(self, line):
			os.system('clear')
		def do_help(self, line):
			help_menu()
		def do_exit(self, line):
			exit(1)
		def do_EOF(self, line):
			exit(1)
		def do_back(self, line):
			os.system("clear")
			main_menu()

			return -1
	WIFI_SHELL().cmdloop()
