Event2Timeline
==============

Event2Timeline is a free tool based on D3js to graph Microsoft Windows sessions events.

How to install
--------------

1) Clone the git repository

1.1) Create a virtual environment with virtualenv and activate it (optional) 

2) Install requirements with `pip install -r requirements.txt`

Alternatively:
2.1) Install python-dateutil (from pip: `pip install python-dateutil`) - http://labix.org/python-dateutil
2.2) Install python-evtx (from pip: `pip install python-evtx`) - http://www.williballenthin.com/evtx/

4) You need to modify a variable in the tool because of the language localisation of the event logs

How to run 
----------

For old EVT files:

1) Convert your eventlogs to CSV format. You can use the free [Microsoft Log Parser 2.2](http://www.microsoft.com/en-us/download/details.aspx?id=24659) 

2) Run `event2timeline.py -c -f csv_filename.csv`

3) Open `timeline/timeline-sessions.html` in your favorite browser

Win 7 EVTX files are supported. Just run `event2timeline.py -x -f Security.evtx`

