import logging

from ConfigParser import Error, ParsingError, RawConfigParser

from defines import *
from ..primitives import Polarization, Sideband, ModSubGroup
from ..r2dbe import R2DBE_INPUTS

module_logger = logging.getLogger(__name__)

class ValidationError(Error):

	def __init__(self, filename):

		# Initialize message
		message = "File contains validation errors: {fname}".format(fname=filename)

		super(ValidationError, self).__init__(msg=message)

		# Filename where config was read from
		self.filename = filename

		# Initialize list of errors
		self.errors = []

	def append(self, description):

		# Add error to list
		self.errors.append(description)

		# Add line to message
		self.message += "\n\t{count:3d}: {desc}".format(count=self.count,desc=description)

	@property
	def count(self):
		return len(self.errors)

class StationConfigParser(RawConfigParser, object):

	def __init__(self, filename=None, parent_logger=module_logger):
		super(StationConfigParser, self).__init__()

		self.logger = logging.getLogger("{name}[fname]".format(name=".".join((parent_logger.name,
		  self.__class__.__name__)), fname=filename))

		if filename is not None:
			self.read(filename)

	def read(self, filename):

		self.filename = filename

		try:
			return super(StationConfigParser, self).read(filename)
		except ParsingError as pe:
			raise pe

	def validate(self, ignore_device_classes=[]):

		# Initialize a ValidationError instance
		ve = ValidationError(self.filename)

		# Check if there is a global section
		try:
			self._val_global_section()

			# Check station option
			try:
				self._val_global_has_station()
			except Error as err:
				ve.append(err.message)

			# Check backends option
			try:
				self._val_global_has_backends(
				  ignore_device_classes=ignore_device_classes)
			except ValidationError as verr:
				for err in verr.errors:
					ve.append(str(err))
			except Error as err:
				ve.append(err.message)

		except Error as err:
			ve.append(err.message)

		if ve.count > 0:
			raise ve

	@property
	def station(self):

		return self.get(GLOBAL_SECTION, GLOBAL_OPTION_STATION)

	@property
	def backends(self):

		val = self.get(GLOBAL_SECTION, GLOBAL_OPTION_BACKENDS)

		return [wbe.strip() for wbe in val.strip().split(',')]

	def backend_bdc(self, backend):

		return self.get(backend, BACKEND_OPTION_BDC)

	def backend_r2dbe(self, backend):

		return self.get(backend, BACKEND_OPTION_R2DBE)

	def backend_mark6(self, backend):

		return self.get(backend, BACKEND_OPTION_MARK6)

	def backend_if_pol_rx_bdc(self, backend, inp):

		# Analog input
		pol = self.get(backend, BACKEND_OPTION_POLARIZATION % inp)
		rx_sb = self.get(backend, BACKEND_OPTION_RECEIVER_SIDEBAND % inp)
		bdc_sb = self.get(backend, BACKEND_OPTION_BLOCKDOWNCONVERTER_SIDEBAND % inp)

		return pol, rx_sb, bdc_sb

	def backend_if_iface(self, backend, inp):

		# Ethernet routing
		mk6_iface_name = self.get(backend, BACKEND_OPTION_IFACE % inp)

		return mk6_iface_name

	def backend_if_modsubgroup(self, backend, inp):

		# Module
		mods = self.get(backend, BACKEND_OPTION_MODULES % inp)

		return mods

	def _val_has_section(self, sec):
		if sec not in self.sections():
			raise Error("Missing section '{sec}'".format(sec=sec))

	def _val_has_option(self, sec, opt):
		if opt not in self.options(sec):
			raise Error("Missing option '{opt}' in section '{sec}'".format(
			  sec=sec, opt=opt))

	def _val_global_section(self):
		self._val_has_section(GLOBAL_SECTION)

	def _val_global_has_station(self):

		sec, opt = GLOBAL_SECTION, GLOBAL_OPTION_STATION

		# Check if it has a station definition
		self._val_has_option(sec, opt)

		# Check if it is a two-character string
		station = self.get(sec, opt)
		if type(station) is not str:
			raise Error("Invalid type '{typ}' option '{sec}.{opt}' (expected {exp})".format(
			  typ=type(station), opt=opt, sec=sec, exp=str))

		if len(station) != 2:
			raise Error("Value of option '{sec}.{opt}' should be exactly two characters long (got '{val}')".format(
			  opt=opt, sec=sec, val=station))

	def _val_global_has_backends(self, ignore_device_classes=[]):

		sec, opt = GLOBAL_SECTION, GLOBAL_OPTION_BACKENDS

		# CHeck if it has a backends defintion
		self._val_has_option(GLOBAL_SECTION, GLOBAL_OPTION_BACKENDS)

		# Check if it is a string
		backends = self.get(sec, opt)
		if type(backends) is not str:
			raise Error("Invalid type '{typ}' for option '{sec}.{opt}' (expected {exp})".format(
			  typ=type(backends), opt=opt, sec=sec, exp=str))

		# Initialize a ValidationError (possible multiple errors)
		verr = ValidationError(self.filename)

		# Expect a comma-separated list (excluding leading / trailing whitespace per item)
		for be in [wbe.strip() for wbe in backends.strip().split(',')]:
			# Check that each list entry is a continuous non-whitespace string
			if len(be.split()) > 1:
				verr.append("Invalid backend identifier '{be}' in list for option '{sec}.{opt}' (no spaces allowed)".format(
				  be=be, opt=opt, sec=sec))

				# In the event of invalid identifier, no further checks for that backend
				continue

			# For valid identifiers, check if it has a matching section
			try:
				self._val_has_section(be)
			except Error as err:
				verr.append("{msg} (each backend identifier needs a matching section)".format(msg=err.message))

				# If no section for this backend, then nothing further to check
				continue

			# Check that this particular backend section is complete
			try:
				self._val_backend_complete(be,
				  ignore_device_classes=ignore_device_classes)
			except ValidationError as verr_below:
				for err in verr_below.errors:
					verr.append(err)

		# If any errors occurred, raise exception
		if verr.count > 0:
			raise verr

	def _val_backend_complete(self, backend, ignore_device_classes=[]):

		# Initialize ValidationError (possible multiple errors)
		verr = ValidationError(self.filename)

		# Check for these once-off options
		all_device_classes = [
		  BACKEND_OPTION_BDC,
		  BACKEND_OPTION_R2DBE,
		  BACKEND_OPTION_MARK6,
		]
		for ignore in ignore_device_classes:
			try:
				self.logger.info("Ignoring device class '{cls}'".format(cls=ignore))
				all_device_classes.remove(ignore)
			except ValueError as ve:
				self.logger.warning(
				  "Asked to ignore unknown or already ignored device class '{cls}'".format(
				  cls=ignore))
		for opt in all_device_classes:
			try:
				self._val_has_option(backend, opt)
			except Error as err:
				verr.append(err)

		# Check for per-input options
		for inp in R2DBE_INPUTS:
			for opt in [fopt % inp for fopt in [
			  BACKEND_OPTION_POLARIZATION,
			  BACKEND_OPTION_RECEIVER_SIDEBAND,
			  BACKEND_OPTION_BLOCKDOWNCONVERTER_SIDEBAND,
			  BACKEND_OPTION_IFACE,
			  BACKEND_OPTION_MODULES,
			  ]]:
				try:
					self._val_has_option(backend, opt)

					# If option exists, go on to check specific format; these constructors
					# raise ValueError if format is incorrect
					val = self.get(backend, opt)
					if opt == BACKEND_OPTION_POLARIZATION % inp:
						Polarization(polarization_spec=val)
					elif opt == BACKEND_OPTION_RECEIVER_SIDEBAND % inp or opt == BACKEND_OPTION_BLOCKDOWNCONVERTER_SIDEBAND % inp:
						Sideband(sideband_spec=val)
					elif opt == BACKEND_OPTION_MODULES % inp:
						ModSubGroup(val)

				except Error as err:
					verr.append(err)
				except ValueError as err:
					verr.append("{msg} (option is '{sec}.{opt}')".format(
					  msg=str(err), sec=backend, opt=opt))

		# If any error ocurred, raise exception
		if verr.count > 0:
			raise verr
