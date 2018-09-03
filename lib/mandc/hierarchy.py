import logging
import sys

from ConfigParser import RawConfigParser
from threading import Thread
from traceback import format_exception, format_exception_only
from Queue import Queue

from config import StationConfigParser, ValidationError, ParsingError
from mark6 import Mark6
from primitives import IFSignal, SignalPath, EthRoute, ModSubGroup
from r2dbe import R2DBE_INPUTS, R2DBE_NUM_INPUTS, R2dbe
from utils import ExceptingThread

module_logger = logging.getLogger(__name__)

class Backend(object):

	def __init__(self, name, station, r2dbe=None, mark6=None, signal_paths=[SignalPath()], parent_logger=module_logger):
		self.name = name
		self.station = station
		self.r2dbe = r2dbe
		self.mark6 = mark6
		self.signal_paths = signal_paths
		self.logger = logging.getLogger("{name}[name={be}]".format(name=".".join((parent_logger.name, 
		  self.__class__.__name__)), be=self.name))
		self.logger.info("Instantiated backend with (r2dbe={r2dbe}; mark6={mark6})".format(name=self.name,
		  r2dbe=self.r2dbe.host, mark6=self.mark6.host))

	def __repr__(self):
		repr_str = "{name}:%r>>%r" % (self.r2dbe,self.mark6)
		return repr_str.format(name=self.name)

	def setup(self):
		self.r2dbe.setup(self.station, [sp.ifs for sp in self.signal_paths], [sp.ethrt for sp in self.signal_paths])
		self.mark6.setup()

class Station(object):

	def __init__(self, station, backends, parent_logger=module_logger):
		self.station = station
		self.backends = backends
		self.logger = logging.getLogger("{name}[station={station}]".format(name=".".join((parent_logger.name, 
		  self.__class__.__name__)), station=self.station))
		self.logger.info("Configured station with backends [{be_list}]".format(
		  station=self.station, be_list=", ".join(["{be!r}".format(be=be) for be in self.backends.keys()])))

	@classmethod
	def from_file(cls, filename):
		# Create a parser
		scp = StationConfigParser()

		# Read the specified file (includes parsing checks)
		try:
			if len(scp.read(filename)) < 1:
				module_logger.error("Unable to read station configuration file '{0}'".format(filename))
				return
		except ParsingError as pe:
			module_logger.error("{cls} raised {err} with {count} errors: {msg}".format(cls=scp.__class__.__name__,
			  err=pe.__class__.__name__, msg=str(pe), count=len(pe.errors)))
			return

		# Validate the configuration
		try:
			scp.validate()
		except ValidationError as ve:
			module_logger.error("{cls} raised {err} with {count} errors: {msg}".format(cls=scp.__class__.__name__,
			  err=ve.__class__.__name__, msg=str(ve), count=ve.count))
			return

		# If we reach this point, we can assume the config should be applicable
		station = scp.station
		backend_list = scp.backends
		backends = {}
		for be in backend_list:
			r2dbe = R2dbe(scp.backend_r2dbe(be))
			mark6 = Mark6(scp.backend_mark6(be))
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
				backends[be] = Backend(be, station, r2dbe=r2dbe, mark6=mark6, signal_paths=signal_paths)

		return cls(station, backends)

	def setup(self):
		# Initialize queue to keep possible exceptions
		exc_queue = Queue()

		# Start each backend in a separate thread
		threads = [ExceptingThread(exc_queue, target=be.setup, name=be.name)
		  for be in zip(*self.backends.items())[1]]
		[th.start() for th in threads]
		[th.join() for th in threads]

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
