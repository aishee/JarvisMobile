#!/usr/bin/python
# -*- coding: utf-8 -*-

from core import libsex
import os
import random
import cmd

W = '\033[0m'
LP = '\033[1;35m'

libsex.main_menu()
class JarvisM(cmd.Cmd):
    prompt = LP + '[jarvismobile]:~$ ' + W
    def do_help(self, line):
        libsex.help_menu()
    def do_exit(self, line):
        exit(1)
    def do_clear(self, line):
        os.system("clear")
    def do_recon(self, line):
        libsex.recon()
    def do_smtp(self, line):
        libsex.smtp()
    def do_http(self, line):
        libsex.http()
    def do_wifi(self, line):
        libsex.wifi()
    def do_networking(self, line):
        libsex.networking()
    def do_EOF(self, line):
        exit(1)
if __name__ == "__main__":
    JarvisM().cmdloop()
    
