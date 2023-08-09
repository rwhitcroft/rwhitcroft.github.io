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
		return f"{self.prefix}{self.num}.{self.extension}"

	def move(self, delta):
		old = str(self)
		self.num += delta
		print(f"{old} -> {self}")
		os.rename(old, str(self))

files_to_move = []

for file in os.listdir('.'):
	if 'page' in file:
		p = PageFile(file)
		if p.num >= first:
			files_to_move.append(p)

files_to_move.sort(key=lambda x: x.num, reverse=True)

for pagefile in files_to_move:
	pagefile.move(delta)

