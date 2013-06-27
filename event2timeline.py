########################################################################################################
#                                                                                                      #
#   Event2Timeline by @tomchop_ for CERT Societe Generale (@CertSG). Some features added by @Jipe_     #
#                                                                                                      #
#   This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported   #
#   License.http://creativecommons.org/licenses/by-nc-sa/3.0/                                          #
#                                                                                                      #
#   https://cert.societegenerale.com/ - https://github.com/certsocietegenerale/event2timeline/         #
#                                                                                                      #
########################################################################################################

### /!\ You must modify the regexp (s['user'] = re.search) to match the "username" strings in your langage! /!\ ###

import csv, sys, re
import optparse
import datetime
import calendar
import mmap
import contextlib
from dateutil.parser import parse
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view

__description__ = "Event2Timeline"
__version__ = "0.0.1"

eid_regex = re.compile('<EventID Qualifiers="(?P<qualifiers>.*)">(?P<eid>\d+)</EventID>')
sessid_regex = re.compile('<Data Name="TargetLogonId">(?P<session_id>0x[0-9a-fA-F]+)</Data>')
time_regex = re.compile('SystemTime="(?P<time>.*)"')

EVTX_LOGIN = [
				4624 	# An account was successfully logged on
				]	

EVTX_LOGOFF = [
				4647, 	# User initiated logoff
				4634	# An account was logged off
				]

def get_data(xml, name):
	rex = re.compile('<Data Name="%s">(?P<%s>.*)</Data>' % (name, name))
	try:
		return rex.search(xml).group(name)
	except Exception, e:
		return None

def import_xml(filename):

	sessions = {}

	with open(filename, 'r') as f:
		with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
			fh = FileHeader(buf, 0x0)
			count = 0
			for xml, record in evtx_file_xml_view(fh):
				match = eid_regex.search(xml)
				eid = int(match.group('eid'))
				session_id = get_data(xml, 'TargetLogonId')
				
				if eid in EVTX_LOGIN:

					# Insert new session in dictionary
					if session_id:
						sessions[session_id] = {}
					else:
						continue

					info = {}
					info['logon_type'] = get_data(xml, 'LogonType')
					info['eid'] = str(eid)
					info['username'] = get_data(xml, 'TargetDomainName') + '\\' + get_data(xml, 'TargetUserName')
					info['username'] = get_data(xml, 'TargetDomainName') + '\\' + get_data(xml, 'TargetUserName')
					info['ip'] = get_data(xml, 'IpAddress') + ':' + get_data(xml, 'IpPort')
					info['datetime'] = time_regex.search(xml).group('time')

					sessions[session_id]['logon'] = info
				
				elif eid in EVTX_LOGOFF:
					# Ignore if orphan session
					if not sessions.get(session_id):
						continue

					info = {}
					info['eid'] = str(eid)
					info['datetime'] = time_regex.search(xml).group('time')
					sessions[session_id]['logoff'] = info
					
# 4624 - Login 		528
# 4647 - Logoff 	551

#[*] Keys: Category, Description, Data, Domain\User, Date&Time, Source, Computer, Time, Date, Type, Event

	return sessions

def import_csv(filename, delimiter=';', quotechar='"'):

	with open (filename, 'rU') as csvfile:
		logs = []
		print "[*] Reading file %s" % filename
		logreader = csv.DictReader(csvfile, delimiter=delimiter, quotechar=quotechar)

# Audit Success;23/05/2013;09:00:00;23/05/2013 09:00:00;538;Security;Ouverture/Fermeture de session;\S-1-5-21-2052699199-3915784498-1582209984-43253;USER01;"Fermeture de la session utilisateur : Utilisateur :        username Domaine :        userdomain Id. de la session :        (0x0,0xB38D21AB) Type de session :        4"; 

		for log in logreader:
			logs.append(log)

		print "[*] %s lines imported" % (len(logs))
		print '[*] Keys: %s' % ", ".join([i for i in logs[0]])

		return logs[::-1]


def print_log(log):
	for key in log:
		if key == 'log_entries':
			for entry in log[key]:
				for k in entry:
					print "%s:\n%s\n" % (k, entry[k])	
		else:
			print "%s:\n%s\n" % (key, log[key])

def is_session(session_id, log):
	return log['Description'].find(session_id) != -1

def get_logons(user_sessions):
	return [{'start': s['dates'][0], 'end': s['dates'][-1:][0]} for s in user_sessions]

if __name__ == '__main__':

	Parser = optparse.OptionParser(usage='usage: %prog -c|-x -f eventlogfile')
	Parser.add_option('-f', '--filename', dest="eventlogfile", help='path to the evenlog file')
	Parser.add_option('-c', '--csv', action="store_true", default=False, help='Specify the events are in CSV format (for an exported .evt)')
	Parser.add_option('-e', '--evtx', action="store_true", default=False, help='Specify the events are in EVTX format (for a native .evtx)')

	(options, args) = Parser.parse_args()
	
	if not options.eventlogfile:
		Parser.error("You must specify a filename")

	if options.csv:
		logs = import_csv(options.eventlogfile)
	elif options.evtx:
		logs = import_xml(options.eventlogfile)
	else:
		Parser.error("You must specify a file format format (csv or xml)")

	session_list = []
	for log in logs:
		try:
			s = re.search('0x[a-fA-F0-9]{8,8}',log['Description']).group()
			session_list.append(s)
		except Exception, e:
			pass

	print "[*] Session logs: %s" % len(session_list)
	session_list = list(set(session_list)) # uniq
	print "[*] Unique sessions: %s" % len(session_list)

	sessions = []
	for s in session_list:
		sessions.append({'ID': s})

	users = {}

	for s in sessions:
		s['log_entries'] = [l for l in logs if is_session(s['ID'], l)]
		
		s['dates'] = []
		s['timestamps'] = []
		for l in s['log_entries']:
			s['dates'].append(parse(l['Date&Time']))
			s['timestamps'].append(calendar.timegm(parse(l['Date&Time']).timetuple()))
			if l['Event'] in ["540", "538", "528", "551"] :
				try:
					s['user'] = re.search("tilisateur\W+([\w\.\-$]+)\n", l['Description']).group(1)
					#print s['user']
				except Exception, e:	
					print "[-] User not found for session"
					print l
					exit()

		s['dates'].sort()
	
		if users.get(s['user']) == None:
			users[s['user']] = []
		users[s['user']].append(s)
	
	lanes = [u for u in users]

	items = []
	for i, usr in enumerate(users):
		for l in get_logons(users[usr]):
			if l['end'] - l['start'] < datetime.timedelta(seconds=10):
				l['end'] = l['start'] + datetime.timedelta(seconds=10)
			items.append({'lane': i, 'id':str(l['start'])[-8:], 'start': str(l['start']), 'end': str(l['end'])})
		

	time_begin = min([i['start'] for i in items])
	time_end = max([i['end'] for i in items])

	print "[*] Collected sessions from %s to %s" % ((time_begin), (time_end))

	js = open('timeline/evtdata.js','w+')

	js.write("var lanes = %s,\n" % str(lanes))
	js.write("laneLength = lanes.length,\n")
	js.write("items = %s,\n" % items)
	js.write("timeBegin = \'%s\',\n" % time_begin)
	js.write("timeEnd = \'%s\';\n" % time_end)

	js.close()







