#!/usr/bin/env python2.7

import logging
import os.path
import sys

from datetime import datetime, timedelta

from mandc.conf import BACKEND_OPTION_BDC, BACKEND_OPTION_R2DBE, get_vex_list
from mandc import Station
from mandc.utils import TerminalMessenger, configure_logging, UTC

_default_log_basename = os.path.extsep.join([os.path.basename(os.path.splitext(__file__)[0]), "log"])
_default_log = os.path.sep.join([os.path.expanduser("~"), "log",_default_log_basename])

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Execute a triggered vexfile")
	parser.add_argument("-l", "--log-file", dest="log", metavar="FILE", type=str, default=_default_log,
	  help="write log messages to FILE in addition to stdout (default is $HOME/log/{0})".format(_default_log_basename))
	parser.add_argument("-t", "--target-directory", metavar="DIR", type=str, default="/home/oper/remote_ctrl",
	  help="location on Mark6 where schedules are copied and executed (default is '/home/oper/remote_ctrl')")
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
	  help="set logging to level DEBUG")
	parser.add_argument("conf", metavar="CONFIG", type=str,
	  help="backend configuration file")
	args = parser.parse_args()

	# Configure logging
	logger = configure_logging(logfilename=args.log, verbose=args.verbose,
	  stdout_logger=False)

	# Configure UI
	tm = TerminalMessenger()

	# Parse configuration file
	ignore_list = [BACKEND_OPTION_BDC]
	station = Station.from_file(args.conf, tell=tm.tell, ask=tm.ask,
	  ignore_device_classes=ignore_list)

	# Get triggered schedules
	tm.tell("\n############### Locating VEX to execute ###############\n")
	all_vexes = get_vex_list()
	if len(all_vexes) < 1:
		tm.tell("No VEX files found in trigger area, exiting", exclaim=True)
		sys.exit(0)
	tm.tell("Found {0} VEX files in trigger area".format(len(all_vexes)))

	# Prune schedules that have end-times earlier than now
	tm.tell("\nPruning schedules that end in the past")
	now = datetime.utcnow().replace(tzinfo=UTC())
	future_vexes = []
	for v in all_vexes:
		if v.stop < now:
			tm.tell("  - found schedule {v.name} for which end time has passed, skipping".format(
			  v=v))
		else:
			future_vexes.append(v)
	# If no schedules that late enough end time, report and exit
	if len(future_vexes) < 1:
		tm.tell("Found no schedules that end in the future, exiting", exclaim=True)
		sys.exit(0)

	# Check for duplicates on md5sum
	tm.tell("\nChecking for possible duplicate schedules")
	unique_vexes = []
	for v in future_vexes:
		md5s = [u.md5sum for u in unique_vexes]
		if v.md5sum not in md5s:
			unique_vexes.append(v)
		else:
			copy = unique_vexes[md5s.index(v.md5sum)]
			tm.tell("  - '{self}.vex' md5sum matches that of '{other}.vex', " \
			  "not adding to list".format(self=v.basename, other=v.basename))

	# Sort remainers according to start time
	vexes = sorted(unique_vexes)

	# Under normal circumstances, there should be exactly one VEX file left. If
	# that is not the case, print a warning and then ask user to select the file
	# to use from a list.
	tm.tell("")
	if len(vexes) == 0:
		tm.tell("No executable VEX files found. It may be necessary to " \
		  "manually copy the schedule to execute to the trigger area " \
		  "'/srv/vexstore/trigger'. Ask the array scheduler where the " \
		  "schedule file may be found.", exclaim=True)
		sys.exit(0)
	if len(vexes) > 1:
		tm.tell("Multiple executable VEX files are available. Ask the array " \
		  "scheduler for the md5sum of the correct schedule to execute, then " \
		  "select it from the list below.", exclaim=True)
		# Display list and get selection
		texts =   ["{name:>6s}   " \
		  "{basename:>12s}.vex   " \
				 "{start:>15s}   " \
				  "{stop:>15s}   " \
			  "{description:s}".format(name=v.name, basename=v.basename,
			  start=v.start.strftime("%b %d %H:%M:%S"),
				stop=v.stop.strftime("%b %d %H:%M:%S"), description=v.description)
		 for v in vexes]
		options = dict([(repr(v),v) for v in vexes])
		text_dict = dict([(repr(v),t) for v,t in zip(vexes, texts)])
		response = tm.select("\nAvailable schedules:\n--------------------\n" \
			  "{0:>9s}   " \
			  "{1:>6s}   " \
			 "{2:>16s}   " \
			 "{3:>15s}   " \
			 "{4:>15s}   " \
			 "{5:s}\n".format("md5sum","name","filename","start","end","description"),
		  options, text_post_opt="\nEnter schedule to run (%s): ", text_dict=text_dict)
		vex = options[response]
		# Tell user the selected option
		tm.tell("\nSelected {b}.vex (md5sum={m})".format(b=vex.basename,
		  m=vex.md5sum))
	else:
		vex = vexes[0]
		tm.tell("Using {b}.vex, md5sum={m}".format(b=vex.basename,
		  m=vex.md5sum))

	# Set station
	vex.schedule.set_station(station.station)

	# List found scans
	scans = vex.schedule.scans
	tm.tell("\nFound {n} scans for station {s}".format(n=len(scans),
	  s=station.station), exclaim=len(scans)==0)
	if len(scans) == 0:
		sys.exit(0)
	tm.tell("\n{scan:>8}   {start:>14}  {dur:>8}  {src:>12}".format(
	  scan="scan #",start="start",dur="duration",src="source"))
	for i, s in enumerate(scans):
		tm.tell("     {i:3d} - {start:>14}  {dur:>7}s  {src:>12}".format(i=i+1,
		  src=s.source, start=s.start.strftime("%jd-%Hh%Mn%Ss"), dur=s.duration))

	# Ask user to confirm they want to use this schedule:
	if not tm.ask("\nContinue uploading schedule to recorders?"):
		tm.tell("\nUser aborted schedule upload, exiting")
		sys.exit(0)

	# For each recorder, copy VEX, convert to XML, and load
	for be in zip(*station.backends.items())[1]:
		mark6 = be.mark6
		tm.tell("\nLoading schedule to {m6}...".format(m6=mark6.host))

		# Check if schedule is currently running
		if mark6.check_m6cc_running():
			tm.tell("A schedule is currently running on {m6}, " \
			  "will not attempt to process this recorder any further".format(
			  m6=mark6.host), exclaim=True)
			continue

		# Copy VEX
		if mark6.copy_to(selection.filename, args.target_directory):
			tm.tell("  - Copied {vex} to {m6}:{t}".format(vex=selection.filename,
			  m6=mark6.host, t=args.target_directory))
		else:
			tm.tell("Failed to copy {vex} to {m6}:{t}, will not attempt to " \
			  "process this recorder any further".format(vex=selection.filename,
			  m6=mark6.host, t=args.target_directory), exclaim=True)
			continue

		# VEX to XML
		if mark6.vex2xml(args.target_directory, selection.basename):
			tm.tell("  - Converted {vex}.vex to {vex}.xml on {m6}".format(
			  vex=selection.name, m6=mark6.host))
		else:
			tm.tell("Failed to converted {vex}.vex to {vex}.xml on {m6}, " \
			  "will not attempt to process this recorder any further".format(
			  vex=selection.basename, m6=mark6.host), exclaim=True)
			continue

		# Start M6_CC
		if mark6.m6cc(args.target_directory, selection.basename):
			tm.tell("  - Started schedule {vex}.xml on {m6}".format(
			  vex=selection.basename, m6=mark6.host))
		else:
			tm.tell("Failed to start schedule {vex}.xml on {m6}".format(
			  vex=selection.basename, m6=mark6.host), exclaim=True)
