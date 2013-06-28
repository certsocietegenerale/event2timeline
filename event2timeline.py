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

### /!\ You must modify the USERNAME_STRING to match the "username" strings in your langage! /!\ ###

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
__version__ = "0.0.2"

eid_regex = re.compile('<EventID Qualifiers="(?P<qualifiers>.*)">(?P<eid>\d+)</EventID>')
sessid_regex = re.compile('<Data Name="TargetLogonId">(?P<session_id>0x[0-9a-fA-F]+)</Data>')
time_regex = re.compile('SystemTime="(?P<time>.*)"')

EVTX_LOGIN = [
				4624, 	# An account was successfully logged on
				4778,	# RDP - Session connceted / reconnected
				]	

EVTX_LOGOFF = [
				4647, 	# User initiated logoff
				4634,	# An account was logged off
				4779, 	# RDP - Session disconnected
				]

EVT_LOGIN = [i-4096 for i in EVTX_LOGIN] + [540] # Successful network logon (=4624 in EVTX)
EVT_LOGOFF = [i-4096 for i in EVTX_LOGOFF]

USERNAME_STRING = 'tilisateur' ###### MODIFY THIS TO WHICHEVER LANGUAGE YOUR CSV FILE IS ######

def get_data(xml, name):
	rex = re.compile('<Data Name="%s">(?P<%s>.*)</Data>' % (name, name))
	try:
		return rex.search(xml).group(name)
	except Exception, e:
		return None

def import_xml(filename):

	# 4624 - Login 		528
	# 4647 - Logoff 	551

	#[*] Keys: Category, Description, Data, Domain\User, Date&Time, Source, Computer, Time, Date, Type, Event

	sessions = {}
	user_sessions = {}
	count = 0

	with open(filename, 'r') as f:
		print "[*] Reading EVTX file %s" % filename
		with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
			fh = FileHeader(buf, 0x0)
			count = 0
			for xml, record in evtx_file_xml_view(fh):
				if (count % 2000) == 0:
					print "%s records read"
				count +=1

				match = eid_regex.search(xml)
				eid = int(match.group('eid'))
				session_id = get_data(xml, 'TargetLogonId')
				
				# Insert new session in dictionary
				if sessions.get(session_id, None) == None:
					sessions[session_id] = {}

				if eid in EVTX_LOGIN:

					if session_id:
						sessions[session_id] = {}
					else:
						continue

					info = {}
					info['logon_type'] = get_data(xml, 'LogonType')
					info['eid'] = str(eid)
					info['ip'] = get_data(xml, 'IpAddress') + ':' + get_data(xml, 'IpPort')
					info['datetime'] = parse(time_regex.search(xml).group('time')[:-7])

					sessions[session_id][str(eid)] = info
					username = get_data(xml, 'TargetDomainName') + '\\' + get_data(xml, 'TargetUserName')
					sessions[session_id]['username'] = username
				
				elif eid in EVTX_LOGOFF:
					# Ignore if orphan session
					if not sessions.get(session_id, None) == None:
						continue

					info = {}
					info['eid'] = str(eid)
					info['datetime'] = parse(time_regex.search(xml).group('time')[:-7])
					sessions[session_id][str(eid)] = info


	return sessions

def import_csv(filename, delimiter=';', quotechar='"'):

	with open (filename, 'rU') as csvfile:
		logs = []
		print "[*] Reading CSV file %s" % filename
		logreader = csv.DictReader(csvfile, delimiter=delimiter, quotechar=quotechar)

# Audit Success;23/05/2013;09:00:00;23/05/2013 09:00:00;538;Security;Ouverture/Fermeture de session;\S-1-5-21-2052699199-3915784498-1582209984-43253;USER01;"Fermeture de la session utilisateur : Utilisateur :        username Domaine :        userdomain Id. de la session :        (0x0,0xB38D21AB) Type de session :        4"; 

		for log in logreader:
			logs.append(log)

		print "[*] %s lines imported" % (len(logs))
		print '[*] Keys: %s' % ", ".join([i for i in logs[0]])

		# return logs[::-1]

		sessions = {}
		user_sessions = {}

		count = 0

		for log in logs:

			count += 1

			try:
				session_id = re.search('(?P<session_id>0x([0-9a-fA-F]{2,}))', log['Description']).group('session_id')
			except Exception, e:
				continue

			if sessions.get(session_id, None) == None:
				sessions[session_id] = {}

			if int(log['Event']) in EVT_LOGIN:
				info = {}
				info['eid'] = log['Event']
				info['datetime'] = parse(log['Date&Time'])
				
				sessions[session_id][log['Event']] = info
				username = re.search("%s\W+(?P<username>[\w\.\-$]+)\n" %USERNAME_STRING, log['Description']).group('username')
				sessions[session_id]['username'] = username

			elif int(log['Event']) in EVT_LOGOFF:
				if sessions.get(session_id, None) == None: # Avoid orphan sessions
					continue
				info = {}
				info['eid'] = log['Event']
				info['datetime'] = parse(log['Date&Time'])

				sessions[session_id][log['Event']] = info

		print "[*] %s sessions found (%s lines parsed)" % (len(sessions), count)
		return sessions

def sessions2timeline(sessions):

		# generate session list by user
		user_sessions = {}
		for sid in [s for s in sessions if sessions[s].get('username', None) != None]:
			s = sessions[sid]
			
			if user_sessions.get(s['username'], None) == None:
				user_sessions[s['username']] = {}
			
			user_sessions[s['username']][sid] = s
			
		print "[*] Unique users: %s" % len(user_sessions)
				
		lanes = [u for u in user_sessions]

		items = []
		for i, username in enumerate(user_sessions):

			for user_session in get_sessions(user_sessions[username]):
				if user_session['end'] - user_session['start'] < datetime.timedelta(seconds=10):
					user_session['end'] = user_session['start'] + datetime.timedelta(seconds=10)

				items.append({'info': user_session['info'],'lane': i, 'start': str(user_session['start']), 'end': str(user_session['end'])})
			
		time_begin = min([i['start'] for i in items])
		time_end = max([i['end'] for i in items])

		return {'time_begin': time_begin, 'time_end': time_end, 'items': items, 'lanes': lanes}




def get_sessions(user_sessions):
	
	sessions = []

	for sid in user_sessions:
		s = user_sessions[sid]
		start, end = None, None
		for evt in s:
			if evt != 'username':
				if int(evt) in EVT_LOGIN or int(evt) in EVTX_LOGIN: # deal with a login event- look for the smallest date for session start
					if start == None:
						start = s[evt]['datetime']
					elif s[evt]['datetime'] < start:
						start = s[evt]['datetime']
				if int(evt) in EVT_LOGOFF or int(evt) in EVTX_LOGOFF: # deal with a logoff event- look for the biggest date for session start
					if end == None:
						end = s[evt]['datetime']
					elif s[evt]['datetime'] > end:
						end = s[evt]['datetime']

		if end == None:
			end = start
		if start == None:
			start = end

		# remove datetime object, which does not parse well to JS
		for i in s:
			try:
				s[i].pop('datetime')
			except Exception, e:
				pass
		sessions.append({'start': start, 'end': end, 'info': s})
	
	return sessions
	

def print_log(log):
	for key in log:
		for entry in log[key]:
			for k in entry:
				print "%s:\n%s\n" % (k, entry[k])	
		else:
			print "%s:\n%s\n" % (key, log[key])

if __name__ == '__main__':

	Parser = optparse.OptionParser(usage='usage: %prog -c|-x -f eventlogfile')
	Parser.add_option('-f', '--filename', dest="eventlogfile", help='path to the evenlog file')
	Parser.add_option('-c', '--csv', action="store_true", default=False, help='Specify the events are in CSV format (for an exported .evt)')
	Parser.add_option('-e', '--evtx', action="store_true", default=False, help='Specify the events are in EVTX format (for a native .evtx)')

	(options, args) = Parser.parse_args()
	
	if not options.eventlogfile:
		Parser.error("You must specify a filename")

	if options.csv:
		sessions = import_csv(options.eventlogfile)
	elif options.evtx:
		sessions = import_xml(options.eventlogfile)
	else:
		Parser.error("You must specify a file format format (csv or xml)")

	timeline = sessions2timeline(sessions)

	print "[*] Mapped %s sessions from %s to %s" % (len(timeline['items']), timeline['time_begin'], timeline['time_end'])


	js = open('timeline/evtdata.js','w+')

	js.write("var lanes = %s,\n" % str(timeline['lanes']))
	js.write("laneLength = lanes.length,\n")
	js.write("items = %s,\n" % timeline['items'])
	js.write("timeBegin = \'%s\',\n" % timeline['time_begin'])
	js.write("timeEnd = \'%s\';\n" % timeline['time_end'])

	js.close()







