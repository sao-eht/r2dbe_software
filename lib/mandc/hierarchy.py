import logging
import sys

from ConfigParser import RawConfigParser
from threading import Thread
from traceback import format_exception, format_exception_only
from Queue import Queue

from config import StationConfigParser, ValidationError, ParsingError
from mark6 import Mark6
from primitives import IFSignal, SignalPath, EthRoute, ModSubGroup, CheckingDevice
from r2dbe import R2DBE_INPUTS, R2DBE_NUM_INPUTS, R2dbe
from utils import ExceptingThread
from bdc import BDC, BAND_4TO8, BAND_5TO9

module_logger = logging.getLogger(__name__)

class Backend(CheckingDevice):

	def __init__(self, name, station, bdc=None, r2dbe=None, mark6=None, signal_paths=[SignalPath()],
	  parent_logger=module_logger, **kwargs):
		super(Backend, self).__init__(None, **kwargs)
		self.name = name
		self.station = station
		self.bdc = bdc
		self.r2dbe = r2dbe
		self.mark6 = mark6
		self.signal_paths = signal_paths
		self.logger = logging.getLogger("{name}[name={be}]".format(name=".".join((parent_logger.name, 
		  self.__class__.__name__)), be=self.name))
		self.logger.info("Instantiated backend with (r2dbe={r2dbe}; mark6={mark6})".format(name=self.name,
		  r2dbe=self.r2dbe.host, mark6=self.mark6.host))

	def __repr__(self):
		repr_str = "{name}:%r>>%r" % (self.r2dbe,self.mark6.host)
		return repr_str.format(name=self.name)

	def setup(self):
		# BDC: pre-config checks, then setup, then post-config checks
		self.bdc.pre_config_checks()
		ce_count = 0
		for cr in self.bdc.check_results:
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			raise RuntimeError("Encountered {ce} pre-config critical errors for {bdc}, aborting setup for backend {be}".format(
			  ce=ce_count, bdc=self.bdc, be=self))
		self.bdc.setup(BAND_5TO9)
		self.bdc.post_config_checks()
		ce_count = 0
		for cr in self.bdc.check_results:
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			raise RuntimeError("Encountered {ce} post-config critical errors for {bdc}, aborting setup for backend {be}".format(
			  ce=ce_count, bdc=self.bdc, be=self))

		# R2DBE: pre-config checks, then setup, then post-config checks
		self.r2dbe.pre_config_checks()
		ce_count = 0
		for cr in self.r2dbe.check_results:
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			raise RuntimeError("Encountered {ce} pre-config critical errors for {r2}, aborting setup for backend {be}".format(
			  ce=ce_count, r2=self.r2dbe, be=self))
		self.r2dbe.setup(self.station, [sp.ifs for sp in self.signal_paths],
		  [sp.ethrt for sp in self.signal_paths])
		self.r2dbe.post_config_checks()
		ce_count = 0
		for cr in self.r2dbe.check_results:
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			raise RuntimeError("Encountered {ce} post-config critical errors for {r2}, aborting setup for backend {be}".format(
			  ce=ce_count, r2=self.r2dbe, be=self))

		# Mark6: pre-config checks, then setup, then post-config checks
		self.mark6.pre_config_checks()
		ce_count = 0
		for cr in self.mark6.check_results:
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			raise RuntimeError("Encountered {ce} pre-config critical errors for {m6}, aborting setup for backend {be}".format(
			  ce=ce_count, m6=self.mark6.host, be=self))
		self.mark6.setup(self.station, [sp.ethrt for sp in self.signal_paths],
		  [sp.modsg for sp in self.signal_paths])
		self.mark6.post_config_checks()
		ce_count = 0
		for cr in self.mark6.check_results:
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			raise RuntimeError("Encountered {ce} post-config critical errors for {m6}, aborting setup for backend {be}".format(
			  ce=ce_count, m6=self.mark6.host, be=self))

class Station(CheckingDevice):

	def __init__(self, host, station, backends, parent_logger=module_logger, **kwargs):
		super(Station, self).__init__(host, **kwargs)
		self.station = station
		self.backends = backends
		self.logger = logging.getLogger("{name}[station={station}]".format(name=".".join((parent_logger.name, 
		  self.__class__.__name__)), station=self.station))
		self.logger.info("Configured station with backends [{be_list}]".format(
		  station=self.station, be_list=", ".join(["{be!r}".format(be=be) for be in self.backends.keys()])))

	@classmethod
	def from_file(cls, filename, tell=None, ask=None):
		# Create a parser
		scp = StationConfigParser()

		# Read the specified file (includes parsing checks)
		try:
			if len(scp.read(filename)) < 1:
				module_logger.error("Unable to read station configuration file '{0}'".format(filename))
				raise RuntimeError("Unable to read station configuration file")
		except ParsingError as pe:
			module_logger.error("{cls} raised {err} with {count} errors: {msg}".format(cls=scp.__class__.__name__,
			  err=pe.__class__.__name__, msg=str(pe), count=len(pe.errors)))
			raise pe

		# Validate the configuration
		try:
			scp.validate()
		except ValidationError as ve:
			module_logger.error("{cls} raised {err} with {count} errors: {msg}".format(cls=scp.__class__.__name__,
			  err=ve.__class__.__name__, msg=str(ve), count=ve.count))
			raise ve

		# If we reach this point, we can assume the config should be applicable
		station = scp.station
		backend_list = scp.backends

		# Do availability checks
		avail_backends = []
		for be in backend_list:

			avail = True

			bdc_id = scp.backend_bdc(be)
			if not BDC.is_available(bdc_id, tell=tell):
				module_logger.error("Backend device {name} is not available.".format(name=bdc_id))
				avail = False

			r2dbe_id = scp.backend_r2dbe(be)
			if not R2dbe.is_available(r2dbe_id):
				module_logger.error("Backend device {name} is not available.".format(name=r2dbe_id))
				avail = False

			mark6_id = scp.backend_mark6(be)
			if not Mark6.is_available(mark6_id):
				module_logger.error("Backend device {name} is not available.".format(name=mark6_id))
				avail = False

			if avail:
				avail_backends.append(be)

		# There needs to be at least one available backend
		if len(avail_backends) < 1:
			raise RuntimeError("There are not enough backend devices available for a complete signal path")

		backends = {}
		for be in avail_backends:

			bdc_id = scp.backend_bdc(be)
			r2dbe_id = scp.backend_r2dbe(be)
			mark6_id = scp.backend_mark6(be)
			bdc = BDC(bdc_id, tell=tell, ask=ask)
			r2dbe = R2dbe(r2dbe_id, tell=tell, ask=ask)
			mark6 = Mark6(mark6_id, tell=tell, ask=ask)
			signal_paths = [None]*R2DBE_NUM_INPUTS
			for inp in R2DBE_INPUTS:
				# Analog input
				pol, rx_sb, bdc_sb = scp.backend_if_pol_rx_bdc(be, inp)
				ifs = IFSignal(receiver_sideband=rx_sb, blockdownconverter_sideband=bdc_sb, polarization=pol)
				# Ethernet routing
				mk6_iface_name = scp.backend_if_iface(be, inp)
				mac, ip = mark6.get_iface_mac_ip(mk6_iface_name)
				eth_rt = R2dbe.make_default_route_from_destination(mac, ip)
				# Module
				mods = scp.backend_if_modsubgroup(be, inp)
				# Create signal path
				signal_paths[inp] = SignalPath(if_signal=ifs, eth_route=eth_rt, mod_subgroup=mods)

			# Instantiate backend and add
			backends[be] = Backend(be, station, bdc=bdc, r2dbe=r2dbe, mark6=mark6,
			  signal_paths=signal_paths, tell=tell, ask=ask)

		return cls("localhost", station, backends, tell=tell, ask=ask)

	def setup(self):
		# Initialize queue to keep possible exceptions
		exc_queue = Queue()

		# If no user-input required, start backends in parallel threads
		if self.ask is None:
			threads = [ExceptingThread(exc_queue, target=be.setup, name=be.name)
			  for be in zip(*self.backends.items())[1]]
			[th.start() for th in threads]
			[th.join() for th in threads]
		# If user-input required, then backends need setting up in parallel
		else:
			for be in zip(*self.backends.items())[1]:
				try:
					be.setup()
				except Exception as ex:
					# Get last exception
					exc = sys.exc_info()

					# Log occurence
					exc_str = format_exception_only(*exc[:2])
					exc_lines = format_exception(*exc)
					self.logger.error(
					  "Encountered an exception '{ex}' during setup of backend '{be}', traceback follows:\n{tb}".format(
					  ex=exc_str, be=be, tb="".join(exc_lines)))

		# Check if any of the threads encountered an exception
		num_errors = 0
		while not exc_queue.empty():
			num_errors += 1
			name, exc = exc_queue.get_nowait()
			exc_str = format_exception_only(*exc[:2])
			self.logger.critical("An exception occured during setup of backend '{0}'".format(name))

		# If any errors encountered, raise exception
		if num_errors > 0:
			raise RuntimeError("{0} backend(s) failed setup".format(num_errors))
