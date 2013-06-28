Event2Timeline
==============

Event2Timeline is a free tool based on D3js to graph Microsoft Windows sessions events. It parses both EVTX event logs from post Vista systems (Vista, Windows 7, Windows 8), and CSV exports of the legacy EVT log files.

How to install
--------------

- Clone the git repository

- Create a virtual environment with virtualenv and activate it (optional) 

- Install requirements with `pip install -r requirements.txt`

Alternatively:

- Install python-dateutil (from pip: `pip install python-dateutil`) - http://labix.org/python-dateutil

- Install python-evtx (from pip: `pip install python-evtx`) - http://www.williballenthin.com/evtx/

- You need to modify a variable in the tool because of the language localisation of the event logs

How to run 
----------

For old EVT files:

- Convert your eventlogs to CSV format. You can use the free [Microsoft Log Parser 2.2](http://www.microsoft.com/en-us/download/details.aspx?id=24659).

- Run `event2timeline.py -c -f csv_filename.csv`

- Open `timeline/timeline-sessions.html` in your favorite browser

Post-Vista EVTX files are supported. Just run `event2timeline.py -x -f Security.evtx`

Example
-------

![Rendering example](/event2timeline.png "Result after parsing the SANS FOR 508 Security event logs")

