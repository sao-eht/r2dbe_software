#!/usr/bin/env python2.7

import logging

import os.path
import sys

from mandc.conf import BACKEND_OPTION_BDC, BACKEND_OPTION_MARK6
from mandc import Station
from mandc.utils import TerminalMessenger, configure_logging

_default_log_basename = os.path.extsep.join([os.path.basename(os.path.splitext(__file__)[0]), "log"])
_default_log = os.path.sep.join([os.path.expanduser("~"), "log",_default_log_basename])

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Set 2-bit quantization threshold",
	  epilog="Does the threshold setting for all R2DBEs, and optionally all BDCs " \
	  "in the configuration")
	parser.add_argument("-a", "--bdc-attenuators", action="store_true", default=False,
	  help="include BDC attenuators adjustment to improve ADC input power level")
	parser.add_argument("-l", "--log-file", dest="log", metavar="FILE", type=str, default=_default_log,
	  help="write log messages to FILE in addition to stdout (default is $HOME/log/{0})".format(_default_log_basename))
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
	  help="set logging to level DEBUG")
	parser.add_argument("conf", metavar="CONF", type=str,
	  help="backend configuration file")
	args = parser.parse_args()

	# Configure logging
	logger = configure_logging(logfilename=args.log, verbose=args.verbose,
	  stdout_logger=False)

	# Configure UI
	tm = TerminalMessenger()

	# Should configuration include BDC?
	ignore_list = [BACKEND_OPTION_BDC, BACKEND_OPTION_MARK6]
	if args.bdc_attenuators:
		ignore_list.remove(BACKEND_OPTION_BDC)

	# Parse configuration file
	station = Station.from_file(args.conf, tell=tm.tell, ask=tm.ask,
	  ignore_device_classes=ignore_list)

	# Do ALC for each backend
	for be in zip(*station.backends.items())[1]:
		be.alc(digital_only=not args.bdc_attenuators, use_tell=True)
