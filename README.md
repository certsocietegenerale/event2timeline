Event2Timeline
==============

Event2Timeline is a free tool based on D3js to graph Microsoft Windows sessions events.

How to install
--------------

1) Clone the git repository

1.1) Create a virtual environment with virtualenv and activate it (optional) 

2) Install python-dateutil (from pip: `pip install python-dateutil`) - http://labix.org/python-dateutil
3) Install python-evtx (from pip: `pip install python-evtx`) - http://www.williballenthin.com/evtx/

4) You need to modify a regexp in the tool because of the language localisation of the event logs

How to run 
----------

1) Convert your eventlogs to CSV format (native evtx will be supported). 
You can use the free Microsoft Log Parser 2.2 ( http://www.microsoft.com/en-us/download/details.aspx?id=24659 )

2) Run event2timeline.py csv_filename

3) Open timeline/timeline-sessions.html in your favorite browser

