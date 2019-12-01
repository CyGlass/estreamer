#!/usr/bin/env python

# local lib
from estreamer import plugin
from estreamer import streamer
from estreamer import eventrequest
from estreamer import config
from estreamer import message

# standard libs
import socket
import sys
import time as timesleep
import os
import logging
import ConfigParser

# setup plugin directory and load initial plugins
plugin_dir = os.path.dirname(os.path.realpath(__file__)) + '/plugins/'
plugin.Plugin.load_plugins(plugin_dir)
plugin.Plugin.list_plugins()

basedir = os.path.dirname(os.path.realpath(__file__)) + '/'
stamp_file = basedir + 'eStreamer.stamp'


def getLastStamp():
    try:
        with open('estreamer.stamp', 'r') as f:
            stamp = f.read().rstrip()
            return int(stamp)
    except IOError:
        return False

def setLastStamp(stamp):
    try:
        with open('estreamer.stamp', 'w') as f:
            f.write(str(stamp))
    except IOError:
        pass

def main():
    cfg = ConfigParser.ConfigParser()
    cfg.read('estreamer.config')
    STREAM_FLAGS = [x.lstrip(' ') for x in cfg.get('settings', 'event_types').split(',')]
    REQUEST_FLAGS = { k: v for k, v in cfg.items('flags') }

    with streamer.eStreamerConnection('firepower', 8302, basedir + 'client.pkcs12', 'estreamer') as ec:
        last_stamp = getLastStamp() if getLastStamp() else 1
        # make original request
	print str(REQUEST_FLAGS)
        re = eventrequest.RequestEvent(last_stamp, **REQUEST_FLAGS)
        resp = ec.request(re.record)
        # if extended, send stream request
        if config.test_bit(re.flags.from_bytes, 30):
            ser = eventrequest.StreamEventRequest(STREAM_FLAGS)
            resp = ec.request(ser.record)
        # loop over the rest of the responses
        while True:
           if not resp:
               resp = ec.response()
           mh = message.MessageHeader(resp)
           if mh.type == message.MSG_TYPE_NULL:
		continue
         
	   print "Message Type="+str(mh.type) 
           print mh
           print mh.data
	   print len(mh.data.messages) 
           for i in range(0,len(mh.data.messages)):
		print str(i)+": "+str(mh.data.messages[i])

	   if mh.type == message.MSG_TYPE_MessageBundle:
               # get the last timestamp
               mh_obj = mh.data.data[-1]
               if hasattr(mh_obj,'timestamp'): 
                   ts = getattr(mh_obj, 'timestamp')
                   setLastStamp(ts)
               # if it's a message bundle, send a NULL response
               ping_msg = message.MessageHeader(version=1, length=0, type=0, data='')
               resp = ec.request(ping_msg.pack())
           else:
               setLastStamp(mh.data.timestamp)
           print repr(mh)
           for plgin in plugin.Plugin.plugins.values():
               plgin.callback(mh)

if __name__ == "__main__":
    sys.exit(main())
