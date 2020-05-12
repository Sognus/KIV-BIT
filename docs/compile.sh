#!/bin/bash
#run pdflatex a few times
for i in {1..5}
do
		pdflatex bit.tex
	done

	# Clean non-pdf files
	rm bit.aux 2> /dev/null
	rm bit.log 2> /dev/null
	rm bit.lot 2> /dev/null
	rm bit.out 2> /dev/null
	rm bit.toc 2> /dev/null
