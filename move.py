#!/usr/bin/env python3

import os, re, sys

first = int(sys.argv[1])
delta = int(sys.argv[2])

class PageFile:
	def __init__(self, filename):
		m = re.search('(\d+)', filename)
		self.prefix = "page"
		self.num = int(m[0])
		self.extension = "markdown"

	def __str__(self):
		return f"{self.prefix}{self.num}"

	def move(self, delta):
		orig = str(self)
		self.num += delta
		new = str(self)
		print(f"moving {orig} -> {self}")

files = os.listdir('.')

for file in files:
	if 'page' in file:
		p = PageFile(file)
		if p.num >= first:
			p.move(delta)
