SOURCES = ps1.tex
OUTPUTS = ps1.dvi ps1.pdf
TEMPS = ps1.aux ps1.log ps1.out

all: clean dvi pdf

dvi: $(SOURCES)
	latex $^
	rm -rf  $(TEMPS)

pdf: $(SOURCES)
	pdflatex $^
	rm -rf  $(TEMPS)

clean:
	rm -rf $(TEMPS) $(OUTPUTS)
