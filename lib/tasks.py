#!/usr/bin/env python
#coding=utf-8
import time
import re

from publish.ansiblelib import ansible_run, generate_play, install

from lib.worker import app

@app.task
def send_flow_to_ansible(hosts_list=[], project='', file='', flow=''):
    '''
    推送发布任务到ansible
    tasks.send_flow_to_ansible.delay(***)
    :param hosts:
    :param project:
    :param file:
    :return:
    '''

    play = generate_play(srcfile=file, hosts=hosts_list, name=project)
    ansible_run(hosts=hosts_list, play_source=play, flow='')


@app.task
def playtest():
    install()