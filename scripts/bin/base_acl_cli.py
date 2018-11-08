#!/usr/bin/python

import nas_acl
import argparse
import sys
import cps

_valid_ops=['show-table','show-entry','delete-entry','delete-table','create-counter','append-counter','delete-counter','show-stats']
_valid_match_fields=['SRC_IP','DST_IP','OUT_INTF','SRC_MAC','DST_MAC','L4_SRC_PORT','L4_DST_PORT','SRC_INTF','IP_PROTOCOL']

_valid_stages=['EGRESS','INGRESS']
_entry_actions=['DROP','FORWARD','COPY_TO_CPU','COPY_TO_CPU_AND_FORWARD']

parser = argparse.ArgumentParser(description='This tool will perform ACL \
	related command line operations',formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-op',choices=_valid_ops,help='Show all acl entries \
	in the table',action='store',required=True)
parser.add_argument('-table-priority',action='store',type=int,help='The ACL table priority',required=False)
parser.add_argument('-table-match',choices=_valid_match_fields,action='append',help='These are the possible match fields',required=False)
parser.add_argument('-table-stage',help='This is the stage at which to install the ACL',choices=_valid_stages,required=False,default='INGRESS')

parser.add_argument('-entry-sipv4',help="Source IPv4 address and mask (eg. 1.1.1.1/255.255.255.0)",required=False)
parser.add_argument('-entry-sport',required=False,type=int)
parser.add_argument('-entry-action',choices=_entry_actions,help='The action to take',required=False)

parser.add_argument('-entry-prio',help='The ACL entry priority',type=int,required=False)
parser.add_argument('-entry-dipv4',help='The destination IPv4 (eg.. 1.1.1.1/255.255.255.0)',required=False)
parser.add_argument('-entry-dport',help='The destination port',required=False)
parser.add_argument('-i','--in_interface',help='The incoming interface id',action='store',required=False)
parser.add_argument('-l','--lag_interface',help='The incoming interface Lag id',action='store',required=False)
parser.add_argument('-o','--out_interface',help='The outgoing interface id',action='store',required=False)
parser.add_argument('--mac_source',help='The source MAC address',action='store',required=False)
parser.add_argument('-p','--protocol',help='The IP protocol type (TCP/UDP/ICMP)',action='store')
parser.add_argument('--mac_destination',help='The destination MAC address',action='store',required=False)
parser.add_argument('-table-id',help='The table ID',required=False)
parser.add_argument('-entry-id',help='The entry ID',required=False)
parser.add_argument('-counter-id',help='Get the counter id from create-counter function',required=False)



parser.add_argument('-d',help='Enable debug operations',action='store_true',required=False)
_args = vars(parser.parse_args())


def __show_table():
  print "ACL Tables display..."
  print "Key is the instance ID of the acl table"
  nas_acl.print_table()


def __create_counter():
  if _args['table_id']==None:
    print('Missing mandatory attributes to create counter-Required table-id')
    sys.exit(1)
  counter_id = nas_acl.create_counter(table_id=int(_args['table_id']),types=['PACKET'])
  return counter_id

def __append_counter():
    if _args['table_id']==None or _args['entry_id']==None or _args['counter_id']==None:
        print('Missing mandatory attributes to append the counter id to entry- Required table-id, entry-id and counter-id')
        sys.exit(1)
    nas_acl.append_entry_action(int(_args['table_id']),int(_args['entry_id']),'SET_COUNTER',int(_args['counter_id']))



def __delete_counter():
  if _args['table_id']==None or _args['counter_id']==None:
    print('Missing attributes-provide table-id and counter-id as arguments')
    sys.exit(1)
  nas_acl.delete_counter(int(_args['table_id']),int(_args['counter_id']))
  sys.exit(0)

def __show_stats():
  if _args['table_id']==None or _args['counter_id']==None:
    print ('Missing attributes to show stats - Needed table-id and counter-id')
    sys.exit(1)
  nas_acl.print_stats(int(_args['table_id']),int(_args['counter_id']))


def __delete_table():
  if _args['table_id']==None:
    print('Missing mandatory attributes to delete table- required table-id and prerequisit is to delete the entry before deleting table using delete-entry')
    sys.exit(1)
  nas_acl.delete_table(int(_args['table_id']))
  print('Table deleted...')
  sys.exit(0)

def __show_entry():
  nas_acl.print_entry()

def __delete_entry():
  if _args['table_id']==None or _args['entry_id']==None:
    print('Missing mandatory attributes to delete entry - required table-id and entry-id')
    sys.exit(1)
  nas_acl.delete_entry(int(_args['table_id']),int(_args['entry_id']))
  print ('Entry deleted')

__ops={
  'show-table':__show_table,
  'show-stats':__show_stats,
  'append-counter':__append_counter,
  'create-counter':__create_counter,
  'delete-table':__delete_table,
  'show-entry':__show_entry,
  'delete-entry':__delete_entry,
  'delete-counter':__delete_counter,
}

def main():
  if _args['entry_sipv4']!=None:
    _sep = _args['entry_sipv4'].split('/')
    if len(_sep)!=2:
      print("Missing IPv4 Mask or incomplete address")
      sys.exit(1)
    _args['entry_smask4'] = _sep[1]
    _args['entry_sipv4'] = _sep[0]

  if _args['entry_dipv4']!=None:
    _sep = _args['entry_dipv4'].split('/')
    if len(_sep)!=2:
      print("Missing IPv4 Mask or incomplete address")
      sys.exit(1)
    _args['entry_dmask4'] = _sep[1]
    _args['entry_dipv4'] = _sep[0]

  if _args['d']:
    print _args

  _op = _args['op']
  __ops[_op]()
  sys.exit(0)

if __name__ == "__main__":
  main()

