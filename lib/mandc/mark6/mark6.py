import logging

import json
import os
from datetime import datetime, timedelta
from subprocess import Popen, PIPE
from struct import pack
from tempfile import NamedTemporaryFile
from time import sleep

from ..primitives.base import IPAddress, MACAddress
from ..primitives.devices import CheckingDevice
from defines import *
from ..data import VDIFFrame
from ..r2dbe import R2DBE_VTP_SIZE, R2DBE_VDIF_SIZE

module_logger = logging.getLogger(__name__)

def _system_call(cmd):
	p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
	stdout, stderr = p.communicate()
	rc = p.returncode
	module_logger.debug("Call '{0}' returned {1:d}\n<stdout>{2}</stdout><stderr>{3}</stderr>".format(cmd, rc, stdout, 
	  stderr))
	# Return call return code, stdout, and stderr as 3-tuple
	return (rc, stdout, stderr)

class ModuleStateError(RuntimeError):
	pass

class ModuleStatus(object):

	def __init__(self, qresp):
		self._qresp = qresp
		self.group_ref = qresp.params[0]
		self.slot = int(qresp.params[1])
		self.eMSN = qresp.params[2]
		self.ndisks_dsc = int(qresp.params[3])
		self.ndisks_reg = int(qresp.params[4])
		self.gb_remain = 0 if not qresp.params[5].isdigit() else int(qresp.params[5])
		self.gb_total = int(qresp.params[6])
		self.status1 = qresp.params[7]
		self.status2 = qresp.params[8]
		self.type = qresp.params[9]

	def __str__(self):
		return ":".join(self._qresp.params)

	@property
	def MSN(self):
		return self.eMSN.split("/")[0]

class ScanCheck(object):

	def __init__(self, qresp):
		self.group_ref = qresp.params[0]
		self.scan_no = int(qresp.params[1])
		self.label = qresp.params[2]
		self.nstreams = int(qresp.params[3])
		self.label = qresp.params[4]
		self.status = qresp.params[5]
		self.data_format = qresp.params[6]
		self.start = datetime.strptime(qresp.params[7], "%Yy%jd%Hh%Mm%Ss")
		self.duration = float(qresp.params[8])
		self.size = float(qresp.params[9])
		self.rate = float(qresp.params[10])
		self.missing = int(qresp.params[11])

	def __str__(self):
		return ":".join(self._qresp.params)

class Response(object):

	def __init__(self, params):
		# return code
		self.rc = int(params[0])
		# cplane return code
		self.cprc = int(params[1])
		# parameters
		self.params = params[2:]

	@classmethod
	def string2params(cls, s):
		params = s.split(":")
		params[-1] = params[-1].split(";")[0]

		return params

class QueryResponse(Response):

	def __init__(self, name, *args):
		super(QueryResponse, self).__init__(*args)
		# query name
		self.name = name

	@classmethod
	def from_string(cls, qs):
		# Take care of possible '?' in the response, a la scan_check data? or time?
		qsegments = qs.split("?")
		query = qsegments[0]
		response = "?".join(qsegments[1:])
		qname = query.split("!")[1]
		params = Response.string2params(response)

		return cls(qname, params)

	def __repr__(self):
		return "!{s.name}?{s.rc}:{s.cprc}:{param};".format(s=self,param=":".join(self.params))

class CommandResponse(Response):

	def __init__(self, name, *args):
		super(CommandResponse, self).__init__(*args)
		# command name
		self.name = name

	@classmethod
	def from_string(cls, cs):
		command, response = cs.split("=")
		cname = command.split("!")[1]
		params = Response.string2params(response)

		return cls(cname, params)

	def __repr__(self):
		return "!{s.name}={s.rc}:{s.cprc}:{param};".format(s=self,param=":".join(self.params))

class InputStream(object):

	def __init__(self, label, data_format, payload_size, payload_offset, psn_offset,
	  iface_id, filter_address, portno, subgroup):
		self._label = label
		self._data_format = data_format
		self._payload_size = int(payload_size)
		self._payload_offset = int(payload_offset)
		self._psn_offset = int(psn_offset)
		self._iface_id = iface_id
		self._filter_address = filter_address
		self._portno = int(portno)
		self._subgroup = subgroup

	@classmethod
	def from_eth_iface_mod(cls, label, eth, iface, mod, src_type=R2DBE_SOURCE_TYPE):
		# eth is EthRoute, mod is ModSubGroup
		ip = str(eth.dst.ip)
		port = str(eth.dst.port)
		mod = str(mod)

		if src_type not in SOURCE_TYPES:
			raise RuntimeError("Unsupported source type '{src}' for input stream definition".format(
			  src_type))

		if src_type == R2DBE_SOURCE_TYPE:
			data_format = R2DBE_DATA_FORMAT
			payload_size = R2DBE_PAYLOAD_SIZE
			payload_offset = R2DBE_PAYLOAD_OFFSET
			psn_offset = R2DBE_PSN_OFFSET

		return cls(label, data_format, payload_size, payload_offset, psn_offset,
		  iface, ip, port, mod)

	def __eq__(self, other):
		if not self.label == other.label:
			# Comparison on label useful, since it's derived from station code
			return False
		if not self.data_format == other.data_format:
			return False
		if not self.payload_size == other.payload_size:
			return False
		if not self.payload_offset == other.payload_offset:
			return False
		if not self.psn_offset == other.psn_offset:
			return False
		if not self.iface_id == other.iface_id:
			return False
		if not self.filter_address == other.filter_address:
			return False
		if not self.portno == other.portno:
			return False
		if not self.subgroup == other.subgroup:
			return False
		return True

	def __ne__(self, other):
		return not self == other

	def __repr__(self):
		return ":".join([str(p) for p in self.params])

	@property
	def params(self):
		return [self.label, self.data_format, self.payload_size, self.payload_offset,
		  self.psn_offset, self.iface_id, self.filter_address, self.portno, self.subgroup]

	@property
	def label(self):
		return self._label

	@property
	def data_format(self):
		return self._data_format

	@property
	def payload_size(self):
		return self._payload_size

	@property
	def payload_offset(self):
		return self._payload_offset

	@property
	def psn_offset(self):
		return self._psn_offset

	@property
	def iface_id(self):
		return self._iface_id

	@property
	def filter_address(self):
		return self._filter_address

	@property
	def portno(self):
		return self._portno

	@property
	def subgroup(self):
		return self._subgroup

class Mark6Config(object):

	def __init__(self, station, input_stream0, input_stream1):
		self._station = station
		self._input_streams = [input_stream0, input_stream1]

	@property
	def station(self):
		return self._station

	@property
	def input_streams(self):
		return self._input_streams

	def __eq__(self, other):
		if self.station != other.station:
			module_logger.debug("Mark6Config station mismatch")
			return False
		ours = self.input_streams
		theirs = other.input_streams
		for o,t in zip(ours, theirs):
			if o != t:
				module_logger.debug("Mark6Config input stream mismatch")
				return False
		return True

	def __ne__(self, other):
		return not self == other

	def __repr__(self):
		return "{s!r};{i0!r};{i1!r}".format(s=self.station,
		  i0=self._input_streams[0], i1=self._input_streams[1])

class Mark6(CheckingDevice):

	CHECK_CODE_HIGH = 5000

	@classmethod
	def valid_msn(cls, msn):
		# Only check length should be 8, ignore other rules (apparently not enforced)
		if len(msn) != 8:
			return False
		return True

	def __init__(self, host, mark6_user=MARK6_DEFAULT_USER, parent_logger=module_logger, **kwargs):
		super(Mark6, self).__init__(host, **kwargs)
		self.user = mark6_user
		self.logger = logging.getLogger("{name}[host={host!r}]".format(name=".".join((parent_logger.name,
		  self.__class__.__name__)), host=self.host,))
		# connect to Mark6
		if self.host:
			pass #@test@self._connect()!#

	def __repr__(self):
		repr_str = "{user}@{host}"
		return repr_str.format(user=self.user, host=self.host)

	def _connect(self):
		pass

	def _daclient_call(self, op, cmd, *args):
		cmd_args = "{cmd}{q}{param}".format(q=op, cmd=cmd, param=":".join([str(arg) for arg in args]))
		echo_cmd = "echo '{cmd}' | da-client".format(cmd=cmd_args)
		rc, stdout, stderr = self._system_call(echo_cmd)
		if rc != 0:
			self.logger.error("da-client call failed, received error code {code} with message '{msg}'".format(code=rc,
			  msg=stderr))
			raise RuntimeError("da-client call failed")
		# Extract response message
		response = stdout
		# Start with "!<cmd>?" or "!<cmd>=" section
		response = response[response.find("!{cmd}{q}".format(q=op,cmd=cmd)):]
		# End before next ">>"
		response = response[:response.find(">>")]
		# Trim any whitespace characters
		response = response.strip()

		return response, cmd_args

	def _daclient_query(self, cmd, *args):
		rx, tx = self._daclient_call("?", cmd, *args)

		self.logger.debug("Sent '{tx}', got back '{rx}'".format(tx=tx,rx=rx))

		qr = QueryResponse.from_string(rx)
		if not qr.rc == VSI_SUCCESS:
			raise RuntimeError("Query failed on {mk6.host}, sent '{tx}', received '{rx}'".format(
			  mk6=self,tx=tx,rx=rx))

		# cplane error should log, without raising error
		if qr.cprc != CPLANE_SUCCESS:
			self.logger.error("cplane response code {qr.cprc}, full response '{qr!r}'".format(
			  qr=qr))

		return qr

	def _daclient_set(self, cmd, *args):
		rx, tx = self._daclient_call("=", cmd, *args)

		self.logger.debug("Sent '{tx}', got back '{rx}'".format(tx=tx,rx=rx))

		sr = CommandResponse.from_string(rx)

		# VSI error should raise exception
		if not sr.rc == VSI_SUCCESS:
			raise RuntimeError("Command failed on {mk6.host}, sent '{tx}', received '{rx}'".format(
			  mk6=self,tx=tx,rx=rx))

		# cplane error should log, without raising error
		if sr.cprc != CPLANE_SUCCESS:
			self.logger.error("cplane response code {sr.cprc}, full response '{sr!r}'".format(
			  sr=sr))

		return sr

	def _python_call(self, py_code):
		# Excute Python source in py_code and return stdout
		with NamedTemporaryFile(mode="w+",suffix=".py",delete=True) as tmp_fh:
			tmp_fh.write(py_code)
			tmp_fh.flush()
			py_cmd = "cat {tmp} | ssh {user}@{host} python -".format(tmp=tmp_fh.name, user=self.user, host=self.host)
			rc, stdout, stderr = _system_call(py_cmd)
			if rc != 0:
				self.logger.error("Python call failed, received error code {code} with message '{msg}'".format(code=rc,
				  msg=stderr))
				raise RuntimeError("Python call failed")

			return stdout

	def _safe_python_call(self, py_code, *args):
		# Execute Python source and return variables using json.dumps()
		wrapper_code = "" \
		  "try:\n" \
		  "    import json\n" \
		  "    {code}\n" \
		  "    print json.dumps((True, ({rvar})))\n" \
		  "except Exception as ex:\n" \
		  "    print json.dumps((False, (str(ex.__class__), str(ex))))\n".format(code="\n    ".join(py_code.split("\n")),
		  rvar=" ".join(["{0},".format(a) for a in args]))
		rstr = self._python_call(wrapper_code)
		res, rv = json.loads(rstr)

		# Log possible error
		if not res:
			ex_name = rv[0]
			ex_msg = rv[1]
			self.logger.error("A {name} exception occurred during Python call: {msg}".format(name=ex_name, msg=ex_msg))

		# Then return the result and return value
		return res, dict(zip(args,[r for r in rv]))

	def _system_call(self, cmd):
		# Execute cmd remotely. Note that cmd is wrapped in double quotes, so any internal
		# quoting should use single quotes.
		ssh_cmd = 'ssh {user}@{host} "{cmd}"'.format(user=self.user, host=self.host, cmd=cmd)
		return _system_call(ssh_cmd)

	def copy_to(self, local_file, target_path, create_path=True):
		# Copy file from local machine (where Python object instance exists) to Mark6
		if create_path:
			rc, so, se = self._system_call("mkdir -p {t}".format(t=target_path))
			if rc != 0:
				self.logger.error(
				  "Failed to create target path {t} on {me}, received error {c} with message '{m}'".format(
				  t=target_path, me=self, c=rc, m=se))

		# Even if target path creation failed, try to continue
		remote_file = local_file.split(os.sep)[-1]
		rc, so, se = _system_call("scp {l} {u}@{h}:{t}/{r}".format(l=local_file,
		  u=self.user, h=self.host, t=target_path, r=remote_file))
		if rc != 0:
			self.logger.error("Failed to copy {l} to {u}@{h}:{t}, " \
			  "received error {c} with message '{m}'".format(l=local_file,
			  u=self.user, h=self.host, t=target_path, c=rc, m=se))

		return rc == 0

	def vex2xml(self, path, filename, station=None):
		v2x = "{p}/{e}".format(p=EXEC_VEX2XML_PATH, e=EXEC_VEX2XML)

		if station is None:
			# Try to use station from object config
			self.logger.info("No station set in vex2xml, trying object_config")
			try:
				station = self.object_config.station
			except AttributeError:
				self.logger.error("No object_config.station, cannot run vex2xml")
				return False

		# Do call
		rc, so, se = self._system_call("cd {rp}; {v2x} -f {rf}.vex -s {s}".format(
		  rp=path, v2x=v2x, rf=filename, s=station))
		if rc != 0:
			self.logger.error("Failed to execute vex2xml.py for file {rf} in {rp} on {u}@{h}, " \
			  "received error {c} with message '{m}'".format(rf=filename,
			  rp=path, u=self.user, h=self.host, c=rc, m=se))

		# Check XML created
		rc, so, se = self._system_call("ls {rp}/{rf}.xml".format(
		  rp=path, v2x=v2x, rf=filename))
		if rc != 0:
			self.logger.error("Check for existence of {rp}/{rf}.xml failed, " \
			  "received error {c} with message '{m}'".format(rf=filename,
			  rp=path, u=self.user, h=self.host, c=rc, m=se))

		return rc == 0

	def m6cc(self, path, filename):
		m6cc = "{p}/{e}".format(p=EXEC_M6CC_PATH,e=EXEC_M6CC)
		log1 = "{rp}/stdout.{rf}".format(rp=path, rf=filename)
		log2= "{rp}/stderr.{rf}".format(rp=path, rf=filename)

		# Do call
		rc, so, se = self._system_call(
		  "cd {rp}; nohup {m6cc} -f {rf}.xml >{l1} 2>{l2} </dev/null &".format(
		  rp=path, m6cc=m6cc, rf=filename, l1=log1, l2=log2))
		if rc != 0:
			self.logger.error("Failed to execute M6_CC for file {rf} in {rp} on {u}@{h}, " \
			  "received error {c} with message '{m}'".format(rf=filename,
			  rp=path, u=self.user, h=self.host, c=rc, m=se))
			return False

		if not self.check_m6cc_running():
			self.logger.warning("{e} does not seem to be running, check {rp}/screenlog.*".format(
			  e=EXEC_M6CC, rp=path))
			return False

		return True

	def check_m6cc_running(self):
		# Check if process still running
		rc, so, se = self._system_call("pgrep {e}".format(e=EXEC_M6CC))
		if rc in [0,1]:
			return rc == 0

		self.logger.error("Failed to check if {e} still running, " \
		  "received error {c} with message '{m}'".format(c=rc, m=se, e=EXEC_M6CC))

	def datetime(self):
		code_str = "" \
		  "from datetime import datetime\n" \
		  "t = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')\n"

		# Get call result
		res, rv = self._safe_python_call(code_str, "t")

		if res:
			timestamp = str(rv["t"])
			t = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")

		return t

	def capture_vdif(self, iface, port, timeout=3.0, timed_capture=False,
	  vtp_bytes=R2DBE_VTP_SIZE, vdif_bytes=R2DBE_VDIF_SIZE):
		vdifsize = vtp_bytes + vdif_bytes
		code_str = "" \
		  "from socket import socket, AF_INET, SOCK_DGRAM\n" \
		  "from datetime import datetime\n" \
		  "import os\n" \
		  "ip = os.popen('/sbin/ifconfig {iface} | egrep -o \"inet addr.+Bcast\" | egrep -o \"([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}\"').read().strip()\n" \
		  "sock_addr = (ip, {portno})\n" \
		  "sock = socket(AF_INET, SOCK_DGRAM)\n" \
		  "sock.settimeout({timeout})\n" \
		  "sock.bind(sock_addr)\n" \
		  "t1 = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')\n" \
		  "data, addr = sock.recvfrom({vdifsize})\n" \
		  "t2 = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')\n" \
		  "data = [ord(d) for d in data]\n" \
		  "t_d_t = (t1, data, t2)\n".format(iface=iface, portno=port, timeout=timeout, vdifsize=vdifsize)

		# Get call result
		res, rv = self._safe_python_call(code_str, "t_d_t")

		if res:
			data = rv["t_d_t"][1][vtp_bytes:]
			bin_data = pack("<%dB" % vdif_bytes, *data)
			vdif = VDIFFrame.from_bin(bin_data)

			if not timed_capture:
				return vdif

			t1 = datetime.strptime(rv["t_d_t"][0], "%Y-%m-%d %H:%M:%S.%f")
			t2 = datetime.strptime(rv["t_d_t"][2], "%Y-%m-%d %H:%M:%S.%f")
			return vdif, t1, t2

	def data_receive_check(self, iface, port):
		# Try to receive data
		v = self.capture_vdif(iface, port)

		# If result is None, fail
		if v is None:
			return False

		# Possibly some checks to determine if really VDIF
		# ...

		return True

	def vv_proxy(self, iface, port):

		# Do a timed capture
		res = self.capture_vdif(iface, port, timed_capture=True)
		# None return means timeout
		if res is None:
				return None
		# Expand successful capture into VDIF and timestamps
		vd, t1, t2 = res

		# Error margin
		margin = (t2 - t1).total_seconds()/2

		# Set zero time to half-way between t1 and t2
		t0 = t1 + timedelta(seconds=margin)

		# Convert VDIF timestamp to offset-naive
		tv_str = vd.datetime().strftime("%Y-%m-%d %H:%M:%S.%f")
		tv = datetime.strptime(tv_str, "%Y-%m-%d %H:%M:%S.%f")

		return (tv - t0).total_seconds(), margin

	def vv_check(self, iface, port):
		res = self.vv_proxy(iface, port)
		if res is not None:
			delta, sigma = res
			if abs(delta) <= VV_MAX_OFFSET:
				return True

		return False

	def record_check(self, duration=10, wait=30):
		# Enqueue a record
		scan = datetime.utcnow().strftime("%jd-%Hh%Mm%Ss")
		exp = "recchk"
		station = "00"

		self.logger.info("Enqueued recording, exp={e} station={s} scan={n}".format(
		  e=exp, s=station, n=scan))

		rv = self.enqueue_record(duration, start=wait, exp=exp, station=station,
		  scan=scan)

		self.logger.debug("Enqueue_record returned {rv}".format(rv=rv))

		if not rv:
			return False

		# Wait until after record is supposed to be finished, add 3s extra time
		sleep(duration + wait + 3)

		# Make sure recording is switched off
		rv = self.dequeue_record()

		self.logger.debug("Enqueue_record returned {rv}".format(rv=rv))

		if not rv:
			return False

		# Do a scan check
		name = "_".join([exp, station, scan])
		sc = self.scan_check(name)

		# Check a few properties of scan check result
		if sc is None:
			# If None returned, cplane error
			self.logger.error("record_check failed: received cplane error code")
			return False
		if sc.duration < 0.99*duration:
			# Expect data to span 99% of duration
			self.logger.error("record_check failed: duration too short, " \
			  "expected {e}s, found {d}s".format(e=duration, d=sc.duration))
			return False
		if sc.size < 0.99*2*R2DBE_PACKET_RATE*R2DBE_PAYLOAD_SIZE/1e9:
			# Expect data to be 99% complete
			self.logger.error("record_check failed: not enough data, " \
			  "expected {e}GB, found {s}GB".format(s=sc.size,
			  e=2*R2DBE_PACKET_RATE*R2DBE_PAYLOAD_SIZE/1e9))
			return False

		# Other checks that produce warnings, but still success
		if sc.status not in ["OK"]:
			self.logger.warning("scan_check status is '{s}'".format(s=sc.status))

		return True

	def get_iface_mac_ip(self, iface):
		code_str = "" \
		  "import os\n" \
		  "mac = os.popen('/sbin/ifconfig %s | egrep HWaddr | egrep -o \"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\"').read().strip()\n" \
		  "ip = os.popen('/sbin/ifconfig %s | egrep -o \"inet addr.+Bcast\" | egrep -o \"([0-9]{1,3}\.){3}[0-9]{1,3}\"').read().strip()" % (iface, iface)

		# Get call result
		res, rv = self._safe_python_call(code_str, "mac", "ip")

		if res:
			mac_str = str(rv["mac"])
			ip_str = str(rv["ip"])
			return MACAddress(mac_str), IPAddress(ip_str)

	def get_mac_ip_iface(self, mac, ip):
		code_str = "" \
		  "import os\n" \
		  "iface = ''\n" \
		  "for line in os.popen('ifconfig').read().splitlines():\n" \
		  "    if line and line[0].isspace():\n" \
		  "        continue\n" \
		  "    words = line.split()\n" \
		  "    if not words:\n" \
		  "        continue\n" \
		  "    x = words[0]\n" \
		  "    mac = os.popen('/sbin/ifconfig %s | egrep HWaddr | egrep -o \"([0-9a-fA-F]{{2}}:){{5}}[0-9a-fA-F]{{2}}\"' % x).read().strip()\n" \
		  "    ip = os.popen('/sbin/ifconfig %s | egrep -o \"inet addr.+Bcast\" | egrep -o \"([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}\"' % x).read().strip()\n" \
		  "    if mac == '{mac}' and ip == '{ip}':\n" \
		  "        iface = x".format(mac=mac, ip=ip)

		# Get call result
		res, rv = self._safe_python_call(code_str, "iface")
		if res:
			if len(rv["iface"]) > 0:
				return rv["iface"]

	def get_module_status(self, mod_n):
		qreply = self._daclient_query("mstat", str(mod_n))

		return ModuleStatus(qreply)

	def compare_module_dual_status(self, s1=None, s2=None, mod_n=MARK6_MODULES):
		# Make a list of requested modules
		if not type(mod_n) == list:
			mod_n = [mod_n]

		# Compare each module against statuses
		for m in mod_n:
			mstat = self.get_module_status(m)
			if s1 is not None and mstat.status1 != s1:
				return False
			if s2 is not None and mstat.status2 != s2:
				return False

		return True

	def mod_init(self, mod_n, MSN, new=False, diskno=MOD_DISKNO, mod_type=MOD_TYPE_SG):
		args = [mod_n, diskno, MSN, mod_type]
		if new:
			args.extend(["new"])
		sresp = self._daclient_set("mod_init",*args)

		return sresp.cprc == CPLANE_SUCCESS

	def group_new(self, grp=GROUP_REF):
		sresp = self._daclient_set("group","new",grp)

		return sresp.cprc == CPLANE_SUCCESS

	def group_mount(self, grp=GROUP_REF):
		sresp = self._daclient_set("group","mount",grp)

		return sresp.cprc == CPLANE_SUCCESS

	def group_open(self, grp=GROUP_REF):
		sresp = self._daclient_set("group","open",grp)

		return sresp.cprc == CPLANE_SUCCESS

	def group_close(self, grp=GROUP_REF):
		sresp = self._daclient_set("group","close",grp)

		return sresp.cprc == CPLANE_SUCCESS

	def group_unmount(self, grp=GROUP_REF):
		sresp = self._daclient_set("group","unmount",grp)

		return sresp.cprc == CPLANE_SUCCESS

	def group_unprotect(self, grp=GROUP_REF):
		sresp = self._daclient_set("group","unprotect",grp)

		return sresp.cprc == CPLANE_SUCCESS

	def add_input_stream(self, input_stream):
		params = ["add"] + input_stream.params
		sresp = self._daclient_set("input_stream",*params)

		return sresp.cprc == CPLANE_SUCCESS

	def delete_input_stream(self, label):
		params = ["delete", label]
		sresp = self._daclient_set("input_stream",*params)

		return sresp.cprc == CPLANE_SUCCESS

	def get_input_streams(self):
		qresp = self._daclient_query("input_stream")

		input_streams = []
		for n in range(len(qresp.params)/9):
			sub = qresp.params[n*9:(n+1)*9]
			input_streams.append(InputStream(*sub))

		return input_streams

	def commit_input_streams(self):
		sresp = self._daclient_set("input_stream", "commit")

		return sresp.cprc == CPLANE_SUCCESS

	def enqueue_record(self, length, start=None, exp="exp", station="XX", scan=None,
	  rate_GBps=2):
		# Set the recording start time
		utc_now = datetime.utcnow()
		if type(start) is int:
			# Start-time is offset in seconds
			start = utc_now + timedelta(seconds=start)
		if type(start) is not datetime:
			self.logger.error(
			  "Expect recording start time to be integer or datetime, but found {typ}".format(
			  typ=type(start)))
			return False

		# Check that start time is in the future
		if start <= utc_now:
			self.logger.error("Start time {s} not in future, it is now {n}".format(
			  s=start, n=utc_now))
			return False

		# Set automatic scan name if necessary
		if scan is None:
			scan = start.strftime("%jd-%Hh%Mm%Ss")

		# Issue record command
		params = [start.strftime("%Yy%jd%Hh%Mm%Ss"), length, length*rate_GBps,
		  scan, exp, station]
		sresp = self._daclient_set("record", *params)

		return sresp.cprc == CPLANE_SUCCESS

	def dequeue_record(self):
		sresp = self._daclient_set("record", "off")

		return sresp.cprc == CPLANE_SUCCESS

	def scan_check(self, name):
		qreply = self._daclient_query("scan_check", name)

		if qreply.cprc == CPLANE_SUCCESS:
			return ScanCheck(qreply)

		self.logger.error("scan_check returned failure, cplane code {c}".format(
		  c=qreply.cprc))

		return None

	def config_object(self, cfg):
		self._station = cfg.station
		self._input_streams = cfg.input_streams

	def config_device(self, cfg):

		# Do super's config first
		super(Mark6, self).config_device(cfg)

		# Get modules in proper state
		self.logger.info("Attempting to put modules in closed unprotected state")
						#~ # Check if proper grouping...
						#~ proper_grouping = True
						#~ for m in MARK6_MODULES:
							#~ mstat = self.get_module_status(m)
							#~ proper_grouping = proper_grouping and (mstat.group_ref == GROUP_REF)
						#~ if not proper_grouping:
							#~ # ...if not, re-initialize...
							#~ self.logger.warning("Modules not grouped properly, re-initializing and grouping")
							#~ for m in MARK6_MODULES:
								#~ mstat = self.get_module_status(m)
								#~ self.logger.info("Initializing module {m} with MSN '{e}'".format(
								  #~ m=m, e=mstat.MSN))
								#~ self.mod_init(m, mstat.MSN)

		if self.compare_module_dual_status(s1="initialized"):
			self.logger.info("Found all modules initialized, forming new group")
			self.group_new()

		if self.compare_module_dual_status(s1="unmounted"):
			self.logger.info("Found all modules unmounted, mounting")
			self.group_mount()

		if self.compare_module_dual_status(s1="open"):
			self.logger.info("Found all modules open, closing")
			self.group_close()

		if self.compare_module_dual_status(s1="closed"):
			if self.compare_module_dual_status(s2="protected"):
				self.logger.info("Found all modules closed:protected, unprotecting")
				self.group_unprotect()

		# Modules should now be in closed:unprotected state
		if not self.compare_module_dual_status(s1="closed",s2="unprotected"):
			self.logger.error("Unable to put modules in closed:unprotected state, aborting setup. " \
			  "Try restarting dplane and cplane, then try again.")
			raise ModuleStateError("Failed to put modules in closed:unprotected state. " \
			  "Try restarting dplane and cplane, then try again.")

		# If there are any input streams, delete them
		self.logger.info("Removing existing input streams if any")
		for input_stream in self.get_input_streams():
			self.delete_input_stream(input_stream.label)

		# Add input streams and commit
		self.logger.info("Adding and committing new input streams")
		self.add_input_stream(cfg.input_streams[0])
		self.add_input_stream(cfg.input_streams[1])
		self.commit_input_streams()

		# Open modules
		self.logger.info("Open modules for recording")
		self.group_open()

		# Check if modules are open:ready
		if not self.compare_module_dual_status(s1="open",s2="ready"):
			self.logger.error("Unable to put modules in open:ready state, setup failed. " \
			  "Try restarting dplane and cplane, then try again.")
			raise ModuleStateError("Failed to put modules in open:ready state. " \
			  "Try restarting dplane and cplane, then try again.")

	def setup(self, station, inputs, outputs):

		# Create Mark6Config from the given parameters
		iface0 = self.get_mac_ip_iface(inputs[0].dst.mac, inputs[0].dst.ip)
		input_stream0 = InputStream.from_eth_iface_mod("{sc}0".format(sc=station),
		  inputs[0], iface0, outputs[0])
		iface1 = self.get_mac_ip_iface(inputs[1].dst.mac, inputs[1].dst.ip)
		input_stream1 = InputStream.from_eth_iface_mod("{sc}1".format(sc=station),
		  inputs[1], iface1, outputs[1])
		mc = Mark6Config(station, input_stream0, input_stream1)

		# Set the object configuration
		self.config_object(mc)

		# Check if the device config matches the object
		if self.device_matches_object():
			self.logger.info("Device configuration {name} matches specification".format(
			  name=self.host))
			if not self.ask("Mark6 {name} configuration matches that from file, re-configure?".format(
				  name=self.host), exclaim=True):
				self.logger.info("Device configuration for {name} will be left unaltered".format(
					  name=self.host))
				return
			else:
				self.logger.info("Device configuration for {name} will be overwritten".format(
				  name=self.host))

		# If device config does not match object, or ask response said to overwrite
		self.config_device(mc)

	def _count_disks(self):
		"""Return number of disks found by lsscsi minus 1 system disk"""
		rc, stdo, stde = self._system_call("lsscsi | grep -c disk")
		if rc == 0:

			return int(stdo)-1

		return -1

	def _ntpq_pn(self):
		"""Return offset magnitude in seconds, or -1 on error"""
		rc, stdo, stde = self._system_call("ntpq -pn")
		if rc == 0:
			lines = stdo.split("\n")
			for l in lines[2:]:
				if l[0] != "*":
					continue

				# We identified the system peer
				tally_remote, refid, st, t, when, poll, reach, delay, offset, jitter = lines[-2].split()
				tally = tally_remote[0]
				remote = tally_remote[1:]
				st = int(st)
				t = {"u":"unicast", "b":"broadcast", "l":"local"}[t]

				return abs(float(offset) / 1000.)

		return -1

	def _dplane_running(self):
		"""Return True if pgrep finds a process named dplane"""
		rc, stdo, stde = self._system_call("pgrep dplane")

		return rc == 0

	def _cplane_running(self):
		"""Return True if pgrep finds a process named cplane"""
		rc, stdo, stde = self._system_call("pgrep cplane")

		return rc == 0

	@property
	def device_is_configured(self):
		"""Check if the device is configured.

		For a Mark6 device this is True if all of the following conditions are
		met:
		  1. The modules are in open-ready state
		  2. Exactly two input streams exist
		"""

		# Modules should be in open-ready state
		if not self.compare_module_dual_status(s1="open", s2="ready"):
			self.logger.debug("Device not configured, modules not open:ready")
			return False

		# Input streams should exist
		if len(self.get_input_streams()) != len(MARK6_INPUTS):
			self.logger.debug("Device not configured, correct number of input streams not defined")
			return False

		return True

	@property
	def object_config(self):
		try:
			rc = Mark6Config(self._station, self._input_streams[0],
			  self._input_streams[1])
			return rc
		except:
			return None

	@property
	def device_config(self):
		try:
			input_streams = self.get_input_streams()
			# Station code is first two characters in input_stream label
			station = input_streams[0].label[:2]
			rc = Mark6Config(station, input_streams[0], input_streams[1])
			return rc
		except:
			return None

	def pre_config_checks(self):

		# Do super's pre-config checks first
		super(Mark6, self).pre_config_checks()

		# Compile the checklist
		checklist = [
		  ("lsscsi should return a total of {num} data disks".format(num=LSSCSI_DISKS),
		    self._count_disks, LSSCSI_DISKS, self.CHK_EQ, True,
		    self.CHECK_CODE_HIGH + 21, [
		      "Check that all modules properly inserted and keyed on",
		      "Check that module cables properly attached",
		      "Try to key off all modules, then key them back on using recommended procedure",
		      "Key off all modules, reboot Mark6, then key them back on",]),
		  ("ntpq should show system peer with less than {off} seconds offset".format(off=NTPQ_MAX_OFFSET),
		    self._ntpq_pn, NTPQ_MAX_OFFSET, self.CHK_LT, False,
		    self.CHECK_CODE_HIGH + 22, [
		      "Restart NTP service on Mark6",
		      "Check that Mark6 /etc/ntp.conf has control computer as a server",]),
		  ("dplane should be running", self._dplane_running, None, None, True,
		    self.CHECK_CODE_HIGH + 23, [
		      "Try 'ps aux | grep dplane' on Mark6",
		      "Try '/etc/init.d/dplane start' as root on Mark6",]),
		  ("cplane should be running", self._cplane_running, None, None, True,
		    self.CHECK_CODE_HIGH + 24, [
		      "Try 'ps aux | grep cplane' on Mark6",
		      "Make sure dplane is running, then try '/etc/init.d/cplane start' as root on Mark6",]
		    ),
		]

		# Run this class's checklist
		self.do_checklist(checklist)

	def post_config_checks(self):

		# Do super's pre-config checks first
		super(Mark6, self).post_config_checks()

		# Compile the checklist
		eth0 = self.object_config.input_streams[0].iface_id
		port0 = self.object_config.input_streams[0].portno
		eth1 = self.object_config.input_streams[1].iface_id
		port1 = self.object_config.input_streams[1].portno
		checklist = [
		]

		# Run this class's checklist
		self.do_checklist(checklist)
