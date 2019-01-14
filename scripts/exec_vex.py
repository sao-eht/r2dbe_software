#!/usr/bin/env python2.7

import logging
import os.path
import sys

from datetime import datetime, timedelta

from mandc.config import BACKEND_OPTION_BDC, BACKEND_OPTION_R2DBE, get_vex_list
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
	all_vexes = get_vex_list()
	if len(all_vexes) < 1:
		tm.tell("No VEX files found in trigger area, exiting", exclaim=True)
		sys.exit(0)
	tm.tell("Found {0} VEX files in trigger area".format(len(all_vexes)))

	# Prune schedules that have end-times earlier than now
	now = datetime.utcnow().replace(tzinfo=UTC())
	vexes = []
	for v in all_vexes:
		if v.stop < now:
			tm.tell("Found schedule {v.name} for which end time has passed, skipping".format(
			  v=v))
		else:
			vexes.append(v)
	# If no schedules that late enough end time, report and exit
	if len(vexes) < 1:
		tm.tell("Found no schedules that end in the future, exiting", exclaim=True)
		sys.exit(0)

	# Sort remainers according to start time
	vexes = sorted(vexes)
	# Display list and get selection
	options = dict([(v.name,v) for v in vexes])
	response = tm.select("\n\nAvailable schedules:\n\n" \
	  "{0:10} {1:>7}  {2:>15}    {3:>15}  {4}\n".format(
	    "", "md5sum", "start", "end", "description"),
	  options, text_post_opt="\nEnter schedule to run (%s): ")
	selection = options[response]
	# Tell user the selected option
	tm.tell("\n\nSelected schedule '{sched!r}'\n".format(sched=selection))

	# Set station
	selection.schedule.set_station(station.station)

	# List found scans
	scans = selection.schedule.scans
	tm.tell("\nFound {n} scans for station {s}".format(n=len(scans),
	  s=station.station))
	if len(scans) == 0:
		sys.exit(0)
	tm.tell("\n{0:>8}{1:>12}  {2:>14}  {3:>5}".format("","source","start",
	  "duration"))
	for i, s in enumerate(scans):
		tm.tell("  {i:3d} - {s}".format(i=i+1, s=s))

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
			tm.tell("  - Copied {vex} to {m6}:{t}".format(vex=selection.name,
			  m6=mark6.host, t=args.target_directory))
		else:
			tm.tell("Failed to copy {vex} to {m6}:{t}, will not attempt " \
			  "process this recorder any further".format(vex=selection.name,
			  m6=mark6.host, t=args.target_directory), exclaim=True)
			continue

		# VEX to XML
		if mark6.vex2xml(args.target_directory, selection.name):
			tm.tell("  - Converted {vex}.vex to {vex}.xml on {m6}".format(
			  vex=selection.name, m6=mark6.host))
		else:
			tm.tell("Failed to converted {vex}.vex to {vex}.xml on {m6}, " \
			  "will not attempt to process this recorder any further".format(
			  vex=selection.name, m6=mark6.host), exclaim=True)
			continue

		# Start M6_CC
		if mark6.m6cc(args.target_directory, selection.name):
			tm.tell("  - Started schedule {vex}.xml on {m6}".format(
			  vex=selection.name, m6=mark6.host))
		else:
			tm.tell("Failed to start schedule {vex}.xml on {m6}".format(
			  vex=selection.name, m6=mark6.host), exclaim=True)
