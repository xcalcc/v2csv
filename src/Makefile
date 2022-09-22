#  Copyright (C) 2021 Xcalibyte (Shenzhen) Limited.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

CXX=/usr/bin/g++

INCLUDE_FLAGS=-I../include
CXXFLAGS=-g -DDEBUG
CXX11FLAGS=-g -DDEBUG -std=c++11
STATICFALGS=-static

all: executable

release: CXXFLAGS=-O3
release: CXX11FLAGS=-O3 -std=c++11
release: executable

CSVSOURCES=csvreader.cxx
V2CSFSOURCES=v2csf.cxx
VTXTSOURCES=vtxt_diff.cxx
VLIBSOURCES=vtxtlib.cxx
ISSUESOURCES=vtxt_issue.cxx
FPATHSOURCES=filepath.cxx
VRPTSOURCES=vtxt_report.cxx
RULESOURCES=rule_desc.cxx
VRSOURCES=vtxtreader.cxx
XML2VSOURCES=xml2vtxt.cxx
XMLSOURCES=tinyxml2.cxx

CSVOBJECTS=$(CSVSOURCES:.cxx=.o)
V2CSFOBJECTS=$(V2CSFSOURCES:.cxx=.o)
VTXTOBJECTS=$(VTXTSOURCES:.cxx=.o)
VLIBOBJECTS=$(VLIBSOURCES:.cxx=.o)
ISSUEOBJECTS=$(ISSUESOURCES:.cxx=.o)
FPATHOBJECTS=$(FPATHSOURCES:.cxx=.o)
VRPTOBJECTS=$(VRPTSOURCES:.cxx=.o)
RULEOBJECTS=$(RULESOURCES:.cxx=.o)
VROBJECTS=$(VRSOURCES:.cxx=.o)
XML2VOBJECTS=$(XML2VSOURCES:.cxx=.o)
XMLOBJECTS=$(XMLSOURCES:.cxx=.o)

CSVEXECUTABLE=csvreader
V2CSFEXECUTABLE=v2csf
VTXTEXECUTABLE=vtxt_diff
VREXECUTABLE=vtxtreader
XML2VEXECUTABLE=xml2vtxt

executable: $(CSVOBJECTS) $(V2CSFOBJECTS) $(VTXTOBJECTS) $(VLIBOBJECTS) $(ISSUEOBJECTS) $(FPATHOBJECTS) $(VRPTOBJECTS) $(RULEOBJECTS) $(VROBJECTS) $(XML2VOBJECTS) $(XMLOBJECTS) v2csf csvreader vtxt_diff vtxtreader xml2vtxt

clean:
	rm -f $(CSVOBJECTS) $(V2CSFOBJECTS) $(VTXTOBJECTS) $(VLIBOBJECTS) $(ISSUEOBJECTS) $(FPATHOBJECTS) $(VRPTOBJECTS) $(RULEOBJECTS) $(VROBJECTS) $(XML2VOBJECTS) $(XMLOBJECTS) $(CSVEXECUTABLE) $(V2CSFEXECUTABLE) $(VTXTEXECUTABLE) $(VREXECUTABLE) $(XML2VEXECUTABLE)

%.o: %.cxx
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(CSVSOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(V2CSFSOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(VTXTSOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(VLIBSOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(VRPTSOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(FPATHSOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(ISSUESOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(RULESOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(VRSOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(XML2VSOURCES)
	$(CXX) -c $(CXX11FLAGS) $(INCLUDE_FLAGS) $(XMLSOURCES)

csvreader: $(CSVOBJECTS)
	$(CXX) -o csvreader $(STATICFALGS) $(CSVOBJECTS)

v2csf: $(V2CSFOBJECTS)
	$(CXX) -o v2csf $(STATICFALGS) $(V2CSFOBJECTS) $(RULEOBJECTS)

vtxt_diff: $(VTXTOBJECTS)
	$(CXX) -o vtxt_diff $(STATICFALGS) $(VTXTOBJECTS) $(VRPTOBJECTS) $(FPATHOBJECTS) $(ISSUEOBJECTS) $(RULEOBJECTS)

vtxtreader: $(VRPTOBJECTS)
	$(CXX) -o vtxtreader $(STATICFALGS) $(VROBJECTS) $(VRPTOBJECTS) $(FPATHOBJECTS) $(ISSUEOBJECTS) $(RULEOBJECTS)

xml2vtxt: $(XML2VOBJECTS)
	$(CXX) -o xml2vtxt $(STATICFALGS) $(XML2VOBJECTS) $(XMLOBJECTS)
