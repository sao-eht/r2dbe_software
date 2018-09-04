import logging

import json
from datetime import datetime, timedelta
from subprocess import Popen, PIPE
from struct import pack
from tempfile import NamedTemporaryFile

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

class Mark6(CheckingDevice):

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

		return response

	def _daclient_query(self, cmd, *args):
		return self._daclient_call("?", cmd, *args)

	def _daclient_set(self, cmd, *args):
		return self._daclient_call("=", cmd, *args)

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

	def capture_vdif(self, iface, port, timeout=3.0, vtp_bytes=R2DBE_VTP_SIZE, vdif_bytes=R2DBE_VDIF_SIZE):
		vdifsize = vtp_bytes + vdif_bytes
		code_str = "" \
		  "from netifaces import ifaddresses\n" \
		  "from socket import socket, AF_INET, SOCK_DGRAM\n" \
		  "iface = ifaddresses('{iface}')\n" \
		  "sock_addr = (iface[2][0]['addr'], {portno})\n" \
		  "sock = socket(AF_INET, SOCK_DGRAM)\n" \
		  "sock.settimeout({timeout})\n" \
		  "sock.bind(sock_addr)\n" \
		  "data, addr = sock.recvfrom({vdifsize})\n" \
		  "data = [ord(d) for d in data]\n".format(iface=iface, portno=port, timeout=timeout, vdifsize=vdifsize)

		# Get call result
		res, rv = self._safe_python_call(code_str, "data")

		if res:
			data = rv["data"][vtp_bytes:]
			bin_data = pack("<%dB" % vdif_bytes, *data)
			return VDIFFrame.from_bin(bin_data)

	def vv_proxy(self, iface, port):

		# Get time just before packet grab
		t1 = self.datetime()

		# Grab packet
		vd = self.capture_vdif(iface, port)

		# Get time just after packet grab
		t2 = self.datetime()

		# Error margin
		margin = (t2 - t1).total_seconds()/2

		# Set zero time to half-way between t1 and t2
		t0 = t1 + timedelta(seconds=margin)

		# Convert VDIF timestamp to offset-naive
		tv_str = vd.datetime().strftime("%Y-%m-%d %H:%M:%S.%f")
		tv = datetime.strptime(tv_str, "%Y-%m-%d %H:%M:%S.%f")

		return (tv - t0).total_seconds(), margin

	def get_iface_mac_ip(self, iface):
		code_str = "" \
		  "from netifaces import ifaddresses\n" \
		  "iface = ifaddresses('{iface}')\n" \
		  "mac = iface[17][0]['addr']\n" \
		  "ip = iface[2][0]['addr']".format(iface=iface)

		# Get call result
		res, rv = self._safe_python_call(code_str, "mac", "ip")

		if res:
			mac_str = str(rv["mac"])
			ip_str = str(rv["ip"])
			return MACAddress(mac_str), IPAddress(ip_str)

	def get_mac_ip_iface(self, mac, ip):
		code_str = "" \
		  "from netifaces import interfaces, ifaddresses\n" \
		  "iface = ''\n" \
		  "for x in interfaces():\n" \
		  "    itf = ifaddresses(x)\n" \
		  "    mac = itf[17][0]['addr']\n" \
		  "    ip = itf[2][0]['addr']\n" \
		  "    if mac == '{mac}' and ip == '{ip}':\n" \
		  "        iface = x".format(mac=mac, ip=ip)

		# Get call result
		res, rv = self._safe_python_call(code_str, "iface")
		if res:
			if len(rv["iface"]) > 0:
				return rv["iface"]

	def get_module_status(self, mod_n):
		mstat_reply = self._daclient_query("mstat", str(mod_n))
		return (mstat_reply[9], mstat_reply[10])

	def mount_modules(self, grp="1234"):
		return int(self._daclient_set("group","mount",grp).split("=")[1].split(":")[0]) == 0

	def input_streams(self, throughputs):
		for ii, tp in enumerate(throughputs):
			ip = tp["eth"].ip
			port = tp["eth"].port
			iface = tp["iface"]
			mod = tp["mod"]
			params = (
			  "add",
			  "s%d" % ii,
			  "vdif",
			  "8224",
			  "50",
			  "42",
			  str(iface),
			  str(ip),
			  str(port),
			  str(mod),
			)
			# Add the input streams
			self._daclient_set("input_stream",*params)

		# Finally, commit the input streams
		self._daclient_set("input_stream","commit")

	def setup(self, station, inputs, outputs, tell=None, ask=None):

		self.station = station

		# All modules used
		all_mods = "".join(outputs)

		# Mount the modules
		if not self.mount_modules(grp=all_mods):
			self.logger.error("Could not mount modules {mods}".format(mods=all_mods))

		# Get the inputs / outputs
		throughputs = []
		for inp, outp in zip(inputs, outputs): #@test@MARK6_INPUTS:!#
			eth = inp.dst
			iface = self.get_mac_ip_iface(eth.mac, eth.ip)
			mod = outp
			throughputs.append({
			  "eth": eth,
			  "iface": iface,
			  "mod": mod,
			})

		# Define input streams
		self.input_streams(throughputs)

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

	def pre_config_checks(self):

		# Do super's pre-config checks first
		super(Mark6, self).pre_config_checks()

		# Define expected results for some checks
		LSSCSI_DISKS = 32
		NTPQ_MAX_OFFSET = 0.100

		# Compile the checklist
		checklist = [
		  ("lsscsi returns a total of {num} data disks".format(num=LSSCSI_DISKS), self._count_disks, LSSCSI_DISKS, self.CHK_EQ, True),
		  ("ntpq shows system peer with less than {off} seconds offset".format(off=NTPQ_MAX_OFFSET), self._ntpq_pn, NTPQ_MAX_OFFSET, self.CHK_LT, True),
		  ("dplane is running", self._dplane_running, None, None, True),
		  ("cplane is running", self._cplane_running, None, None, True),
		]

		# Run this class's checklist
		self.do_checklist(checklist)

	def post_config_checks(self):

		# Do super's pre-config checks first
		super(Mark6, self).post_config_checks()

		# Compile the checklist
		checklist = []

		# Run this class's checklist
		self.do_checklist(checklist)
