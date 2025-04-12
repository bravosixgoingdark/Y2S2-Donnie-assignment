#!/bin/bash

pandoc --toc -V geometry:paperwidth=8.5in -V geometry:paperheight=11in -V geometry:margin=1in README.md -o HAN23080227.pdf --template eisvogel --listings
