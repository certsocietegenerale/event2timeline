########################################################################################################
#                                                                                                      #
#   Event2Timeline by @tomchop_ for CERT Societe Generale (@CertSG). Some features added by @Jipe_     #
#                                                                                                      #
#   This work is licensed under the GPL License                                                        #
#   http://www.gnu.org/licenses/gpl.txt                                                                #
#                                                                                                      #
#   https://cert.societegenerale.com/ - https://github.com/certsocietegenerale/event2timeline/         #
#                                                                                                      #
########################################################################################################

### /!\ You must modify the USERNAME_STRING to match the "username" strings in your langage! /!\ ###

import csv, re
import optparse
import datetime
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
    4624,  # An account was successfully logged on
    4778,  # RDP - Session connceted / reconnected
]

EVTX_LOGOFF = [
    4647,  # User initiated logoff
    4634,  # An account was logged off
    4779,  # RDP - Session disconnected
]

EVT_LOGIN = [i - 4096 for i in EVTX_LOGIN] + [540]  # Successful network logon (=4624 in EVTX)
EVT_LOGOFF = [i - 4096 for i in EVTX_LOGOFF]

USERNAME_STRING = "tilisateur"  ###### MODIFY THIS TO WHICHEVER LANGUAGE YOUR CSV FILE IS ######


def get_data(xml, name):
    rex = re.compile('<Data Name="%s">(?P<%s>.*)</Data>' % (name, name))
    try:
        return rex.search(xml)[name]
    except Exception:
        return None


def import_xml(filename):

    # 4624 - Login 		528
    # 4647 - Logoff 	551

    # [*] Keys: Category, Description, Data, Domain\User, Date&Time, Source, Computer, Time, Date, Type, Event

    sessions = {}
    count = 0

    with open(filename, "r") as f:
        print(f"[*] Reading EVTX file {filename}")
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            count = 0
            for xml, _ in evtx_file_xml_view(fh):
                if (count % 2000) == 0:
                    print(f"{count} records read")
                count += 1

                match = eid_regex.search(xml)
                eid = int(match.group("eid"))
                session_id = get_data(xml, "TargetLogonId")

                # Insert new session in dictionary
                if sessions.get(session_id, None) == None:
                    sessions[session_id] = {}

                if eid in EVTX_LOGIN:

                    if session_id:
                        sessions[session_id] = {}
                    else:
                        continue

                    info = {}
                    info["logon_type"] = get_data(xml, "LogonType")
                    info["eid"] = str(eid)
                    info["ip"] = get_data(xml, "IpAddress") + ":" + get_data(xml, "IpPort")
                    info["datetime"] = parse(time_regex.search(xml).group("time")[:-7])

                    sessions[session_id][str(eid)] = info
                    username = get_data(xml, "TargetDomainName") + "\\" + get_data(xml, "TargetUserName")
                    sessions[session_id]["username"] = username

                elif eid in EVTX_LOGOFF:
                    # Ignore if orphan session
                    if not sessions.get(session_id, None) == None:
                        continue

                    info = {}
                    info["eid"] = str(eid)
                    info["datetime"] = parse(time_regex.search(xml).group("time")[:-7])
                    sessions[session_id][str(eid)] = info

    return sessions


def import_csv(filename, delimiter=";", quotechar='"'):

    with open(filename, "rU") as csvfile:
        print(f"[*] Reading CSV file {filename}")
        logreader = csv.DictReader(csvfile, delimiter=delimiter, quotechar=quotechar)

        logs = list(logreader)
        print(f"[*] {len(logs)} lines imported")
        print(f'[*] Keys: {", ".join(list(logs[0]))}')

        # return logs[::-1]

        sessions = {}

        count = 0

        for log in logs:

            count += 1

            try:
                session_id = re.search("(?P<session_id>0x([0-9a-fA-F]{2,}))", log["Description"])["session_id"]

            except Exception:
                continue

            if sessions.get(session_id, None) is None:
                sessions[session_id] = {}

            if int(log["Event"]) in EVT_LOGIN:
                info = {"eid": log["Event"], "datetime": parse(log["Date&Time"])}
                sessions[session_id][log["Event"]] = info
                username = re.search(
                    "%s\W+(?P<username>[\w\.\-$]+)\n" % USERNAME_STRING,
                    log["Description"],
                )["username"]

                sessions[session_id]["username"] = username

            elif int(log["Event"]) in EVT_LOGOFF:
                if sessions.get(session_id, None) is None:  # Avoid orphan sessions
                    continue
                info = {"eid": log["Event"], "datetime": parse(log["Date&Time"])}
                sessions[session_id][log["Event"]] = info

        print(f"[*] {len(sessions)} sessions found ({count} lines parsed)")
        return sessions


def sessions2timeline(sessions):

    # generate session list by user
    user_sessions = {}
    for sid in [s for s in sessions if sessions[s].get("username", None) != None]:
        s = sessions[sid]

        if user_sessions.get(s["username"], None) is None:
            user_sessions[s["username"]] = {}

        user_sessions[s["username"]][sid] = s

    print(f"[*] Unique users: {len(user_sessions)}")

    lanes = list(user_sessions)

    items = []
    for i, username in enumerate(user_sessions):

        for user_session in get_sessions(user_sessions[username]):
            if user_session["end"] - user_session["start"] < datetime.timedelta(seconds=10):
                user_session["end"] = user_session["start"] + datetime.timedelta(seconds=10)

            items.append(
                {
                    "info": user_session["info"],
                    "lane": i,
                    "start": str(user_session["start"]),
                    "end": str(user_session["end"]),
                }
            )

    time_begin = min(i["start"] for i in items)
    time_end = max(i["end"] for i in items)

    return {
        "time_begin": time_begin,
        "time_end": time_end,
        "items": items,
        "lanes": lanes,
    }


def get_sessions(user_sessions):

    sessions = []

    for sid in user_sessions:
        s = user_sessions[sid]
        start, end = None, None
        for evt in s:
            if evt != "username":
                if (
                    int(evt) in EVT_LOGIN or int(evt) in EVTX_LOGIN
                ):  # deal with a login event- look for the smallest date for session start
                    if start == None:
                        start = s[evt]["datetime"]
                    elif s[evt]["datetime"] < start:
                        start = s[evt]["datetime"]
                if (
                    int(evt) in EVT_LOGOFF or int(evt) in EVTX_LOGOFF
                ):  # deal with a logoff event- look for the biggest date for session start
                    if end == None:
                        end = s[evt]["datetime"]
                    elif s[evt]["datetime"] > end:
                        end = s[evt]["datetime"]

        if end == None:
            end = start
        if start is None:
            start = end

        # remove datetime object, which does not parse well to JS
        for i in s:
            with contextlib.suppress(Exception):
                s[i].pop("datetime")
        sessions.append({"start": start, "end": end, "info": s})

    return sessions


def print_log(log):
    for key in log:
        for entry in log[key]:
            for k in entry:
                print("%s:\n%s\n" % (k, entry[k]))
        print("%s:\n%s\n" % (key, log[key]))


if __name__ == "__main__":

    Parser = optparse.OptionParser(usage="usage: %prog [-c | -e] -f eventlogfile")
    Parser.add_option("-f", "--filename", dest="eventlogfile", help="path to the evenlog file")
    Parser.add_option(
        "-c",
        "--csv",
        action="store_true",
        default=False,
        help="Specify the events are in CSV format (for an exported .evt)",
    )
    Parser.add_option(
        "-e",
        "--evtx",
        action="store_true",
        default=False,
        help="Specify the events are in EVTX format (for a native .evtx)",
    )

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

    print(f'[*] Mapped {len(timeline["items"])} sessions from {timeline["time_begin"]} to {timeline["time_end"]}')

    with open("timeline/evtdata.js", "w+") as js:
        js.write(f"var lanes = {timeline['lanes']},\n")
        js.write(f"laneLength = lanes.length,\n")
        js.write(f"items = {timeline['items']},\n")
        js.write(f"timeBegin = '{timeline['time_begin']}',\n")
        js.write(f"timeEnd = '{timeline['time_end']}',\n")
        js.write(f"filename = '{options.eventlogfile}';\n")
