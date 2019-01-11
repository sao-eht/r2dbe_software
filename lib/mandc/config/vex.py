import glob
import os

from datetime import datetime, timedelta

from vexparser import vexparser

from mandc.utils import UTC

# Datetime format
DATETIME_FORMAT = "%Yy%jd%Hh%Mm%Ss"

# Section names
SECTION_ANTENNA = '$ANTENNA'
SECTION_BBC = '$BBC'
SECTION_DAS = '$DAS'
SECTION_EXPER = '$EXPER'
SECTION_FREQ = '$FREQ'
SECTION_GLOBAL = '$GLOBAL'
SECTION_HEAD_POS = '$HEAD_POS'
SECTION_IF = '$IF'
SECTION_MODE = '$MODE'
SECTION_PASS_ORDER = '$PASS_ORDER'
SECTION_PHASE_CAL_DETECT = '$PHASE_CAL_DETECT'
SECTION_PROCEDURES = '$PROCEDURES'
SECTION_ROLL = '$ROLL'
SECTION_SCHED = '$SCHED'
SECTION_SITE = '$SITE'
SECTION_SOURCE = '$SOURCE'
SECTION_STATION = '$STATION'
SECTION_TRACKS = '$TRACKS'

# Experiment fields
EXPER_DESC = "exper_description"
EXPER_NAME = "exper_name"
EXPER_START = "exper_nominal_start"
EXPER_STOP = "exper_nominal_stop"

# Schedule entry fields
SCAN_MODE = "mode"
SCAN_SOURCE = "source"
SCAN_START = "start"
SCAN_STATIONS = "station"
SCAN_STATIONS_SEP = ":"

class VexExperiment(object):

	def __init__(self, exper_dict):
		self._description = exper_dict[EXPER_DESC]
		self._name = exper_dict[EXPER_NAME]
		start = datetime.strptime(exper_dict[EXPER_START], DATETIME_FORMAT)
		self._start = start.replace(tzinfo=UTC())
		stop = datetime.strptime(exper_dict[EXPER_STOP], DATETIME_FORMAT)
		self._stop = stop.replace(tzinfo=UTC())

	def __str__(self):
		date_fmt = "%b %d %H:%M:%S"
		time_range = "{begin} -- {end}".format(
		  begin=self.start.strftime(date_fmt),
		  end=self.stop.strftime(date_fmt))

		return "{rng}, {desc}".format(rng=time_range, desc=self.description)

	@property
	def description(self):
		return self._description

	@property
	def name(self):
		return self._name

	@property
	def start(self):
		return self._start

	@property
	def stop(self):
		return self._stop

class VexScan(object):

	def __init__(self, station, mode, source, start, duration):
		self._station = station
		self._mode = mode
		self._source = source
		self._start = start
		self._duration = duration
		self._stop = start + timedelta(seconds=duration)

	def __str__(self):
		return "{me.source:>12}, {b}, {me.duration:>4}s".format(
		  me=self, b=self.start.strftime("%jd-%Hh%Mm%Ss"))

	def __cmp__(self, other):
		ours = self.start
		theirs = other.start
		if ours < theirs:
			return -1
		if ours == theirs:
			return 0
		return 1

	@property
	def duration(self):
		return self._duration

	@property
	def mode(self):
		return self._mode

	@property
	def source(self):
		return self._source

	@property
	def start(self):
		return self._start

	@property
	def station(self):
		return self._station

	@property
	def stop(self):
		return self._stop

class VexSchedule(object):

	def __init__(self, sched_dict):
		self._sched = sched_dict
		self._scans = []

	def set_station(self, code):
		# Initialize scan list to populate
		scans = []

		# Go through all scans
		for k, scan_dict in self._sched.items():
			mode = scan_dict[SCAN_MODE]
			source = scan_dict[SCAN_SOURCE]
			_start = datetime.strptime(scan_dict[SCAN_START],
			  DATETIME_FORMAT).replace(tzinfo=UTC())
			# For each scan, get station list
			stations_list = scan_dict[SCAN_STATIONS] 
			for entry in stations_list:
				# Skip entries not for this station
				station, offset, duration = self._parse_station_line(entry)
				if not station == code:
					continue

				# We have an entry for this station
				start = _start + timedelta(seconds=duration)
				scans.append(VexScan(station, mode, source, start, duration))

				# All other station entries will not be for this station
				break

		# With scan list populated, sort
		self._scans = sorted(scans)

	def _parse_station_line(cls, line):
		elements = [e.strip() for e in line.split(SCAN_STATIONS_SEP)]
		station = elements[0]
		start = int(elements[1].split()[0])
		duration = int(elements[2].split()[0])

		return station, start, duration

	@property
	def scans(self):
		return self._scans

class Vex(object):

	def __init__(self, vex_dict):
		# Add some internal attributes
		self._source = vex_dict["filename"]
		self._checksum = vex_dict["checksum"]
		self._md5sum = vex_dict["md5sum"]

		# Add experiment, assume there is only one
		self._experiment = VexExperiment(vex_dict[SECTION_EXPER].items()[0][1])

		# Add schedule
		self._schedule = VexSchedule(vex_dict[SECTION_SCHED])

	def __cmp__(self, other):
		# Compare on start time
		ours = self.start
		theirs = other.start

		if ours < theirs:
			return -1
		if ours == theirs:
			return 0
		return 1

	def __str__(self):
		return "{md5}, {me.experiment}".format(me=self,md5=self.md5sum[:7])

	def __repr__(self):
		return self.name

	@classmethod
	def from_file(cls, filename):
		vex_dict = vexparser(filename)

		return cls(vex_dict)

	@property
	def filename(self):
		return self._source

	@property
	def checksum(self):
		return self._checksum

	@property
	def experiment(self):
		return self._experiment

	@property
	def md5sum(self):
		return self._md5sum

	@property
	def schedule(self):
		return self._schedule

	# forward .name, .start and .stop from VexExperiment
	@property
	def name(self):
		return self.experiment.name

	@property
	def start(self):
		return self.experiment.start

	@property
	def stop(self):
		return self.experiment.stop

def get_vex_list(staging_or_trigger="trigger",
  root=os.sep.join(["","srv","vexstore"])):
	# Search all available files
	search_pattern = os.sep.join([root, staging_or_trigger, "*.vex"])
	found = glob.glob(search_pattern)

	# For each file, try to parse and create Vex
	vexes = []
	for f in found:
		# May put this in a try..except block
		v = Vex.from_file(f)
		vexes.append(v)

	return vexes

