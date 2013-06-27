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

def import_xml(filename):

	with open(filename, 'r') as f:
		with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
			fh = FileHeader(buf, 0x0)
			for xml, record in evtx_file_xml_view(fh):
				print xml

#[*] Keys: Category, Description, Data, Domain\User, Date&Time, Source, Computer, Time, Date, Type, Event
	
	return logs

def import_csv(filename, delimiter=';', quotechar='"'):

	with open (filename, 'rU') as csvfile:
		logs = []
		print "[*] Reading file %s" % filename
		logreader = csv.DictReader(csvfile, delimiter=delimiter, quotechar=quotechar)
		count = 0

#Audit Success;23/05/2013;09:00:00;23/05/2013 09:00:00;538;Security;Ouverture/Fermeture de session;\S-1-5-21-2052699199-3915784498-1582209984-43253;USER01;"Fermeture de la session utilisateur : Utilisateur :        username Domaine :        userdomain Id. de la session :        (0x0,0xB38D21AB) Type de session :        4"; 

		for log in logreader:
			logs.append(log)
			count += 1

		print "[*] %s lines read, %s lines imported" % (count, len(logs))

		print '[*] Keys: %s' % ", ".join([i for i in logs[0]])

		logs = logs[::-1]

		return logs

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
	Parser.add_option('-x', '--xml', action="store_true", default=False, help='Specify the events are in XML format (for a native .evtx)')

	(options, args) = Parser.parse_args()
	
	if not options.eventlogfile:
		Parser.error("You must specify a file name")

	if options.csv:
		logs = import_csv(options.eventlogfile)
	elif options.xml:
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
	#lanes = [lanes[0]]
	items = []
	for i, usr in enumerate(users):
		for l in get_logons(users[usr]):
			if l['end'] - l['start'] < datetime.timedelta(seconds=10):
				l['end'] = l['start'] + datetime.timedelta(seconds=10)
			items.append({'lane': i, 'id':str(l['start'])[-8:], 'start': str(l['start']), 'end': str(l['end'])})
		#break

	time_begin = min([i['start'] for i in items])
	time_end = max([i['end'] for i in items])

	#delta = time_begin - 10

	# for i in items:
	# 	i['start'] -= delta
	# 	i['end'] -= delta

	# time_begin -= delta
	# time_end -= delta

	#print "[*] Collected sessions from %s to %s" % (datetime.datetime.utcfromtimestamp(time_begin), datetime.datetime.utcfromtimestamp(time_end))
	print "[*] Collected sessions from %s to %s" % ((time_begin), (time_end))

		# var lanes = ["Chinese","Japanese","Korean"],
		# 	laneLength = lanes.length,
		# 	items = [{"lane": 0, "id": "Qin", "start": 5, "end": 205},
		# 			{"lane": 0, "id": "Jin", "start": 265, "end": 420},
		# 			{"lane": 0, "id": "Sui", "start": 580, "end": 615},
		# 			{"lane": 0, "id": "Tang", "start": 620, "end": 900},
		# 			{"lane": 0, "id": "Song", "start": 960, "end": 1265},
		# 			{"lane": 0, "id": "Yuan", "start": 1270, "end": 1365},
		# 			{"lane": 0, "id": "Ming", "start": 1370, "end": 1640},
		# 			{"lane": 0, "id": "Qing", "start": 1645, "end": 1910},
		# 			{"lane": 1, "id": "Yamato", "start": 300, "end": 530},
		# 			{"lane": 1, "id": "Asuka", "start": 550, "end": 700},
		# 			{"lane": 1, "id": "Nara", "start": 710, "end": 790},
		# 			{"lane": 1, "id": "Heian", "start": 800, "end": 1180},
		# 			{"lane": 1, "id": "Kamakura", "start": 1190, "end": 1330},
		# 			{"lane": 1, "id": "Muromachi", "start": 1340, "end": 1560},
		# 			{"lane": 1, "id": "Edo", "start": 1610, "end": 1860},
		# 			{"lane": 1, "id": "Meiji", "start": 1870, "end": 1900},
		# 			{"lane": 1, "id": "Taisho", "start": 1910, "end": 1920},
		# 			{"lane": 1, "id": "Showa", "start": 1925, "end": 1985},
		# 			{"lane": 1, "id": "Heisei", "start": 1990, "end": 1995},
		# 			{"lane": 2, "id": "Three Kingdoms", "start": 10, "end": 670},
		# 			{"lane": 2, "id": "North and South States", "start": 690, "end": 900},
		# 			{"lane": 2, "id": "Goryeo", "start": 920, "end": 1380},
		# 			{"lane": 2, "id": "Joseon", "start": 1390, "end": 1890},
		# 			{"lane": 2, "id": "Korean Empire", "start": 1900, "end": 1945}]
		# 	timeBegin = 0,
		# 	timeEnd = 2000;


	js = open('timeline/evtdata.js','w+')

	js.write("var lanes = %s,\n" % str(lanes))
	js.write("laneLength = lanes.length,\n")
	js.write("items = %s,\n" % items)
	js.write("timeBegin = \'%s\',\n" % time_begin)
	js.write("timeEnd = \'%s\';\n" % time_end)

	js.close()







