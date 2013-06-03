#

import csv, sys, re

from dateutil.parser import parse
import datetime
import calendar

def import_csv(filename, delimiter=';', quotechar='"'):

	with open (filename, 'rU') as csvfile:
		logs = []
		print "[*] Reading file %s" % filename
		#logreader = csv.reader(csvfile, delimiter=delimiter, quotechar=quotechar)
		logreader = csv.DictReader(csvfile, delimiter=delimiter, quotechar=quotechar)
		count = 0

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
	# ret = []
	# for s in user_sessions:
	# 	ret.append({'start': s['timestamps'][0], 'end': s['timestamps'][-1:][0]})
	# 	print "Start %s; End %s" % (s['timestamps'][0], s['timestamps'][-1:][0])
	# return ret

		


if __name__ == '__main__':

	if len(sys.argv) < 2:
		print "Please specify filename"
		exit(-1)

	logs = import_csv(sys.argv[1])

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







