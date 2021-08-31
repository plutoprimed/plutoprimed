# This source code file is released as part of plutoprimed
#
# Copyright 2021 Ústav jaderné fyziky AV ČR, v.v.i
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
# conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
# of conditions and the following disclaimer in the documentation and/or other materials
# provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
# used to endorse or promote products derived from this software without specific prior
# written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import os
import sys
from construct import Struct, PaddedString
import argparse
import json
import iio
import numpy as np
import time
from ctypes import POINTER, c_char
from queue import Queue
from threading import Thread


def native_memview(addr, size):
	return memoryview((c_char*size).from_address(addr))


def ceil(num, granularity):
	return num + granularity - 1 - (num - 1) % granularity


tar_header = Struct(
	"name" / PaddedString(100, "ascii"),
	"mode" / PaddedString(8, "ascii"),
	"uid" / PaddedString(8, "ascii"),
	"gid" / PaddedString(8, "ascii"),
	"size" / PaddedString(12, "ascii"),
	"mtime" / PaddedString(12, "ascii"),
	"chksum" / PaddedString(8, "ascii"),
	"typeflag" / PaddedString(1, "ascii"),
	"linkname" / PaddedString(100, "ascii"),
	"magic" / PaddedString(6, "ascii"),
	"version" / PaddedString(2, "ascii"),
	"uname" / PaddedString(32, "ascii"),
	"gname" / PaddedString(32, "ascii"),
	"devmajor" / PaddedString(8, "ascii"),
	"devminor" / PaddedString(8, "ascii"),
	"prefix" / PaddedString(131, "ascii"),
	"atime" / PaddedString(12, "ascii"),
	"ctime" / PaddedString(12, "ascii"),
	"pad" / PaddedString(12, "ascii")
)


class SigMFSink:
	def __init__(self, **kwargs):
		self.meta = {
			"global": {
				"core:datatype": "cf32_le",
				"core:version": "v0.0.2",
				"core:recorder": "plutoprimed SigMF recorder"
			},
			"captures": [],
			"annotations": [],
		}

		self.meta_global = self.meta["global"]

		if "datatype" in kwargs:
			self.meta_global["core:datatype"] = str(kwargs.pop("datatype"))
		else:
			self.meta_global["core:datatype"] = "cf32_le"

		if "sample_rate" in kwargs:
			self.meta_global["core:sample_rate"] = float(kwargs.pop("sample_rate"))

		if len(kwargs):
			raise ValueError("unknown keyword arguments passed to SigMFSink.__init__: {0}".format(kwargs.keys()))

	def flush(self):
		self._write_metadata()

	def _serialize_meta(self):
		return bytes(json.dumps(self.meta), "ascii")

	def append_samples(self, data):
		raise NotImplementedError()

	def _write_metadata(self):
		raise NotImplementedError()


class SigMFRecording(SigMFSink):
	def __init__(self, filename, **kwargs):
		SigMFSink.__init__(self, **kwargs)

		for suffix in [".sigmf", ".sigmf-data", ".sigmf-meta"]:
			if filename.endswith(suffix):
				filename = filename[:-len(suffix)]
				break

		self.filename = filename
		self.name = os.path.basename(filename)

		self._f_samp = open(filename + ".sigmf-data", "wb")

	def append_samples(self, data):
		self._f_samp.write(data)

	def _write_metadata(self):
		metadata = self._serialize_meta()
		with open(self.filename + ".sigmf-meta", "wb") as f:
			f.write(metadata)


class SigMFArchive(SigMFSink):
	def __init__(self, filename, **kwargs):
		SigMFSink.__init__(self, **kwargs)

		self._f = open(filename, "wb")
		self.name = os.path.basename(filename)

		suffix = ".sigmf"
		if self.name.endswith(suffix):
			self.name = self.name[:-len(suffix)]

		self._off_samp_end = self._off_samp_beg = 512
		self._write_samp_header()

	@classmethod
	def _header(self, name, size):
		d = {
			"name": name,
			"mode": "0000644",
			"uid": "0001750",
			"gid": "0000144",
			"size": f"{size:011o}",
			"mtime": "0"*11,
			"chksum": " "*8,
			"typeflag": "0",
			"magic": "ustar ",
			"version": " ",
			"uname": "user",
			"gname": "users",
			"linkname": "",
			"devmajor": "", 
			"devminor": "",
			"prefix": "",
			"pad": "",
			"atime": "",
			"ctime": "",
		}

		h_sum = sum(tar_header.build(d))%(8**7)
		d["chksum"] = f"{h_sum:o}"
		return tar_header.build(d)

	def _write_samp_header(self):
		self._f.seek(0)
		self._f.write(self._header(
			f"{self.name}.sigmf-data",
			self._off_samp_end - self._off_samp_beg,
		))

	def append_samples(self, data):
		self._f.seek(self._off_samp_end)
		self._f.write(data)
		self._off_samp_end = self._f.seek(0, 1)
		self._write_samp_header()

	def flush(self):
		self._write_metadata()
		self._f.flush()

	def _write_metadata(self):
		off_meta = self._off_samp_end + 511 - (self._off_samp_end - 1) % 512
		self._f.seek(off_meta)

		metadata = self._serialize_meta()

		self._f.write(self._header(
			f"{self.name}.sigmf-meta",
			len(metadata),
		))

		self._f.write(metadata)
		self._f.write(b"\0" * (511 - (self._f.seek(0, 1)-1) % 512))
		self._f.write(b"\0"*512)
		self._f.write(b"\0"*512)


def ad9361_set_samprate(phy, samprate):
	if samprate <= 20000000:
		dec = 4
		taps = [
			-15,-27,-23,-6,17,33,31,9,-23,-47,-45,-13,34,69,67,21,-49,-102,-99,-32,69,146,143,48,-96,-204,-200,-69,129,278,275,97,-170,
			-372,-371,-135,222,494,497,187,-288,-654,-665,-258,376,875,902,363,-500,-1201,-1265,-530,699,1748,1906,845,-1089,-2922,-3424,
			-1697,2326,7714,12821,15921,15921,12821,7714,2326,-1697,-3424,-2922,-1089,845,1906,1748,699,-530,-1265,-1201,-500,363,902,875,
			376,-258,-665,-654,-288,187,497,494,222,-135,-371,-372,-170,97,275,278,129,-69,-200,-204,-96,48,143,146,69,-32,-99,-102,-49,21,
			67,69,34,-13,-45,-47,-23,9,31,33,17,-6,-23,-27,-15
		]
	elif samprate <= 40000000:
		dec = 2
		taps = [
			-0,0,1,-0,-2,0,3,-0,-5,0,8,-0,-11,0,17,-0,-24,0,33,-0,-45,0,61,-0,-80,0,104,-0,-134,0,169,-0,
			-213,0,264,-0,-327,0,401,-0,-489,0,595,-0,-724,0,880,-0,-1075,0,1323,-0,-1652,0,2114,-0,-2819,0,4056,-0,-6883,0,20837,32767,
			20837,0,-6883,-0,4056,0,-2819,-0,2114,0,-1652,-0,1323,0,-1075,-0,880,0,-724,-0,595,0,-489,-0,401,0,-327,-0,264,0,-213,-0,
			169,0,-134,-0,104,0,-80,-0,61,0,-45,-0,33,0,-24,-0,17,0,-11,-0,8,0,-5,-0,3,0,-2,-0,1,0,-0,0
		]
	elif samprate <= 53333333:
		dec = 2
		taps = [
			-4,0,8,-0,-14,0,23,-0,-36,0,52,-0,-75,0,104,-0,-140,0,186,-0,-243,0,314,-0,-400,0,505,-0,-634,0,793,-0,
			-993,0,1247,-0,-1585,0,2056,-0,-2773,0,4022,-0,-6862,0,20830,32767,20830,0,-6862,-0,4022,0,-2773,-0,2056,0,-1585,-0,1247,0,-993,-0,
			793,0,-634,-0,505,0,-400,-0,314,0,-243,-0,186,0,-140,-0,104,0,-75,-0,52,0,-36,-0,23,0,-14,-0,8,0,-4,0
		]
	else:
		dec = 2
		taps = [
			-58,0,83,-0,-127,0,185,-0,-262,0,361,-0,-488,0,648,-0,-853,0,1117,-0,-1466,0,1954,-0,-2689,0,3960,-0,-6825,0,20818,32767,
			20818,0,-6825,-0,3960,0,-2689,-0,1954,0,-1466,-0,1117,0,-853,-0,648,0,-488,-0,361,0,-262,-0,185,0,-127,-0,83,0,-58,0
		]

	if samprate <= 25000000 // 12:
		raise NotImplementedError()

	v0 = phy.find_channel("voltage0", False)
	out = phy.find_channel("out", False)

	out.attrs["voltage_filter_fir_en"].value = "0"
	config = "RX 3 GAIN -6 DEC {0}\nTX 3 GAIN 0 INT {0}\n".format(dec)
	config += "\n".join(["{0},{0}".format(t) for t in taps])
	phy.attrs["filter_fir_config"].value = config
	v0.attrs["sampling_frequency"].value = str(int(samprate))
	out.attrs["voltage_filter_fir_en"].value = "1"


class TriggerChan:
	def __init__(self, dev, label):
		self.dev = dev
		self.label = label
		self.invokes_save = False
		self.knownval = self._regval()

	def check(self):
		newval = self._regval()
		triggered = newval != self.knownval
		self.knownval = newval
		return triggered

	def _regval(self):
		return int(self.dev.attrs["regval"].value)


class Ringbuf:
	def __init__(self, size, dt):
		self.size = size
		self.dt = dt
		self._buf = np.zeros(self.size, dtype=self.dt)

		self.reset()

	def reset(self):
		self.wpos = 0
		self.rpos = 0

	def _unread(self):
		return (self.wpos - self.rpos) % (2*self.size)

	def _space(self):
		return max(self.size - self._unread(), 0)

	def _curb(self):
		if self._unread() > self.size:
			self.rpos = (self.wpos - self.size) % (2*self.size) 
			assert self._unread() == self.size

		self.wpos = self.wpos % (2*self.size)
		self.rpos = self.rpos % (2*self.size)

	def drain(self):
		while self._unread() > 0:
			off = self.rpos % self.size
			piecelen = min(self._unread(), self.size - off)
			yield self._buf[off:off + piecelen]
			self.rpos += piecelen

	def wspace(self):
		off = self.wpos % self.size
		return self._buf[off:]

	def wadvance(self, by):
		self.wpos += by
		self._curb()


def clean():
	print(" "*60, file=sys.stderr, end="\r")


def other_thread_main(tasks_qu, done_qu):
	while True:
		task = tasks_qu.get()
		result = task[0](*task[1:])
		done_qu.put(result)


def pad(f, len):
	f.write(b"\0" * (511 - (len-1) % 512))


def write_samples(fn, metadata, samples_pieces):
	print("writing", file=sys.stderr)
	fout = sys.stdout.buffer
	meta_serialized = bytes(json.dumps(metadata), "ascii")
	fout.write(SigMFArchive._header(fn + ".sigmf-meta", len(meta_serialized)))
	fout.write(meta_serialized)
	pad(fout, len(meta_serialized))

	byte_pieces = [memoryview(p).cast(format="b") for p in samples_pieces]
	tally = sum([len(p) for p in byte_pieces])
	fout.write(SigMFArchive._header(fn + ".sigmf-data", tally))
	for piece in byte_pieces:
		fout.write(piece)
	pad(fout, tally)
	print("done", file=sys.stderr)


def main():
	parser = argparse.ArgumentParser(
		description='record some samples'
	)
	parser.add_argument('--uri', type=str, default="ip:192.168.2.1")
	parser.add_argument('-l', '--lo', '--freq', type=float, default=433e6,
		help='center frequency to tune to in Hz (default: %(default)g)')
	parser.add_argument('-b', '--bw', '--bandwidth', type=float, default=10e6,
		help='RF bandwidth in Hz (default: %(default)g)')
	parser.add_argument('-r', '--sr', '--samprate', type=float, default=4e6,
		help='sample rate in samples per second (default: %(default)g)')
	parser.add_argument('-n', '--triglabels', type=str, default="trig0,trig1",
		help='comma-separated list of labels to use for the two trigger channels (default: %(default)s)')
	parser.add_argument('-t', '--trig', type=str, default="trig0",
		help='trigger channels invoking save of recording (default: %(default)s)')
	parser.add_argument('-p', '--trigpos', type=str, default=0.5,
		help="time position of trigger in produced recordings. this is specified as a proportion"
			+ " of the full recording length. it determines the pre-trigger and post-trigger recording "
			+ " lengths. (default: %(default)s)")
	parser.add_argument('-g', '--gain', type=float, default=-60)
	parser.add_argument('--bufsize', type=int, default=1024*1024*1)
	parser.add_argument('--ringsize', type=int, default=1024*1024*16)
	parser.add_argument('--archive', type=bool)
	parser.add_argument('filename', type=str)
	args = parser.parse_args()

	samplesize = 4
	reclen_ms = args.ringsize / samplesize / args.sr * 1000
	print(f"Will produce recordings {reclen_ms} ms long, with roughly {reclen_ms*args.trigpos} ms"
 	      f" pre-trigger and {reclen_ms*(1-args.trigpos)} ms post-trigger")
	sys.stderr.flush()

	ctx = iio.Context(args.uri)
	print(f"Found {ctx.attrs['hw_model']}", file=sys.stderr)
	metadata = {
		"global": {
			"core:datatype": "ci16_le",
			"core:version": "v0.0.2",
			"core:recorder": "plutoprimed SigMF recorder",
			"core:hw": f"{ctx.attrs['hw_model']}, firmware {ctx.attrs['fw_version']}",
			"core:sample_rate": float(args.sr),
		},
		"captures": [],
		"annotations": [],
	}

	phy = ctx.find_device("ad9361-phy")
	adc = ctx.find_device("cf-ad9361-lpc")
	sample_count = ctx.find_device("sample_count")

	print(args.gain)
	phy.find_channel("voltage0", False).attrs["rf_bandwidth"].value = str(int(args.bw))
	phy.find_channel("altvoltage0", True).attrs["frequency"].value = str(int(args.lo))
	phy.find_channel("voltage0", False).attrs["gain_control_mode"].value = "manual"
	phy.find_channel("voltage0", False).attrs["hardwaregain"].value = str(int(args.gain))
	ad9361_set_samprate(phy, args.sr)

	triggers = [
		TriggerChan(ctx.find_device(f"last_edge_latch{no}"), label)
		for no, label in enumerate(args.triglabels.split(",", 2))
	]
	for triglabel in args.trig.split(","):
		found = False
		for t in triggers:
			if t.label != triglabel:
				continue
			t.invokes_save = True
			found = True
			break
		if not found:
			print("Trigger labeled %s not found (should invoke save of recording)", file=sys.stderr)
			sys.exit(1)

	if args.bufsize % samplesize != 0:
		print("Block buffer size (--bufsize) must be multiple of sample size (4)", file=sys.stderr)
		sys.exit(1)
	if args.ringsize % args.bufsize != 0:
		print("Ringbuffer size (--ringsize) must be multiple of block buffer" \
			  + " size (--bufsize)", file=sys.stderr)
		sys.exit(1)
	if args.ringsize < args.bufsize*2:
		print("Ringbuffer size (--ringsize) is too low", file=sys.stderr)
		sys.exit(1)

	dt = np.dtype([('i', np.dtype('<i2')), ('q', np.dtype('<i2'))])
	#ring = np.zeros(args.ringsize//samplesize, dtype=dt)
	rb = Ringbuf(args.ringsize // samplesize, dt)

	tasks_qu = Queue()
	done_qu = Queue()
	other_thread = Thread(target=other_thread_main, args=(tasks_qu, done_qu))
	other_thread.setDaemon(True)
	other_thread.start()

	sampcount_init = int(sample_count.attrs["regval"].value)
	count = 0

	adc.channels[0].enabled = True
	adc.channels[1].enabled = True
	bufsamples = args.bufsize // samplesize
	buf = iio.Buffer(adc, bufsamples)
	tstart = time.time()

	posttrigger_nsamples = (args.ringsize // samplesize) * (1 - args.trigpos) // bufsamples * bufsamples

	save_ongoing = False
	save_staged_at = None
	annotations = []

	while True:
		try:
			buf.refill()
			count += bufsamples
		except KeyboardInterrupt:
			print("exiting...", file=sys.stderr)
			sys.stderr.flush()
			break

		buf_mv = native_memview(
			iio._buffer_start(buf._buffer),
			iio._buffer_end(buf._buffer) - iio._buffer_start(buf._buffer)
		)

		buf_view = np.frombuffer(buf_mv, dtype=dt)

		head = buf_view[0:8192]
		rssi = np.log10(np.mean(
			head['i'].astype(np.float32)**2+head['q'].astype(np.float32)**2
		))*10-100

		# remove annotations at samples which we are just about to remove from ring buffer
		annotations = [
			(idx, label) for idx, label in annotations
			if idx > count - rb.size
		]

		if not save_ongoing: # if up
			rb.wspace()[:len(buf_view)] = buf_view
			rb.wadvance(len(buf_view))

			if save_staged_at is not None and count >= save_staged_at:
				save_ongoing = True
				metadata["global"]["core:offset"] = count - rb.size
				metadata["annotations"] = [
					{ "core:sample_start": idx, "core:label": label }
					for idx, label in annotations
				]
				tasks_qu.put((write_samples, args.filename + time.strftime("%Y%m%d%H%M%S", time.gmtime()), metadata, rb.drain()))
		else:
			if not done_qu.empty():
				done_qu.get()
				save_ongoing = False
				save_staged_at = None
				rb.reset()

		for tc in triggers:
			if tc.check():
				clean()

				abspos = (tc.knownval - sampcount_init - count + bufsamples) % 2**32 \
						 + count - bufsamples

				if abspos >= count + 3*bufsamples:
					print(f"[{time.time() - tstart:8.2f}] probable overflow (detected when processing {tc.label})", file=sys.stderr)

				annotations.append(
					(abspos, tc.label)
				)
				print(f"[{time.time() - tstart:8.2f}] {tc.label} (rel sample position: {abspos - count}/{bufsamples})", file=sys.stderr)
				sys.stderr.flush()

				if tc.invokes_save:
					save_staged_at = ceil(abspos, bufsamples) + posttrigger_nsamples

		print("refill:{0} rssi:{1:4.1f} unread:{2}\r".format(
			sample_count.attrs["regval"].value,
			rssi, rb._unread(),
		), end="", file=sys.stderr)
		sys.stderr.flush()

	tend = time.time()
	clean()
	print(f"Transferred {count} samples in {tend - tstart:.1f} seconds, which amounts to {count / (tend - tstart):.1f} sps (expected {args.sr:.1f})")


if __name__ == "__main__":
	main()
