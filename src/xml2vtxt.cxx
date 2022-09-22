/*
   Copyright (C) 2019-2022 Xcalibyte (Shenzhen) Limited.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <cassert>

#include "tinyxml2.h"

using namespace std;
using namespace tinyxml2;

char* Get_cmd_option(char** begin, char** end, const std::string& option) {
    char** itr = find(begin, end, option);
    if (itr != end && ++itr != end) {
        return *itr;
    }
    return 0;
}

bool Cmd_option_exists(char** begin, char** end, const std::string& option) {
    return std::find(begin, end, option) != end;
}

string Get_rule(const char* original_rule) {
    const char* CPPCHECK_MISRA_PREFIX = "misra-c2012-";
    const char* VTXT_MISRA_PREFIX = "MSR_";
    string orig_rule(original_rule);
    // rule must start with misra-c2012. if not misra rules, add it to suppressions.txt file in client side.
    assert(orig_rule.rfind(CPPCHECK_MISRA_PREFIX, 0) == 0);
    string tmp_rule = orig_rule.replace(orig_rule.find(CPPCHECK_MISRA_PREFIX), strlen(CPPCHECK_MISRA_PREFIX), "");
    tmp_rule.replace(tmp_rule.find("."), 1, "_");
    return VTXT_MISRA_PREFIX + tmp_rule;
}

string Get_filename(const char* file_path) {
    string tmp_file_path(file_path);
    char sep = '/';
#ifdef _WIN32
    sep = '\\';
#endif
    size_t pos = tmp_file_path.rfind(sep, tmp_file_path.length());
    if(pos != string::npos) {
        string filename = tmp_file_path.substr(pos+1, tmp_file_path.length() - pos);
        return filename.substr(0, tmp_file_path.length());
    }
    return tmp_file_path;
}

string Remove_extension(const string& filename) {
    return filename.substr(0, filename.find_last_of("."));
}

string Remove_extension(char* filename) {
    string tmp_filename(filename);
    return Remove_extension(tmp_filename);
}

void Output_vtxt_header(ofstream& outfile, const char* magic_number) {
    cout<<"Output vtxt header"<<endl;
    string vtxt_version = "0.7.2";
    outfile << "{\"V\", ";
    outfile << magic_number << ", ";
    outfile << vtxt_version << ", ";
    outfile << "0000000000000000000000000000000000000000000000000000000000000000}" << endl;
    cout<<"Output vtxt header end"<<endl;
}

bool cmp(pair<string, int>& a, pair<string, int>& b) {
    return a.second < b.second;
}

void Output_vtxt_file_info(ofstream& outfile, const XMLElement* errors, map<string, int>& file_path_id) {
    cout<<"Output vtxt file info"<<endl;
    outfile << "[" <<endl;

    const char* file_path = NULL;
    int file_number = 0;
    for(const XMLElement* error = errors->FirstChildElement("error"); error != NULL; error = error->NextSiblingElement("error")) {
        error->FirstChildElement("location")->QueryStringAttribute("file", &file_path);
        string file_path_str = file_path;
        if(file_path_id.find(file_path_str) == file_path_id.end()) {
            file_number++;
            file_path_id.insert(pair<string, int>(file_path_str, file_number));
        }
    }

    vector<pair<string, int> > file_path_id_vec;
    copy(file_path_id.begin(), file_path_id.end(), back_inserter<vector<pair<string, int> > >(file_path_id_vec));

    sort(file_path_id_vec.begin(), file_path_id_vec.end(), cmp);

    file_number = 0;
    for(auto& item: file_path_id_vec) {
        file_number++;
        outfile << "  {" <<endl;
        outfile << "    \"fid\" : "<<item.second<<","<<endl;
        outfile << "    \"path\" : \""<<item.first<<"\""<<endl;
        outfile << "  }";
        if(file_number != file_path_id_vec.size()) {
            outfile << ","<<endl;
        } else {
            outfile <<endl;
        }
    }

    outfile << "]" <<endl;
    cout<<"Output vtxt file info end"<<endl;
}

void Output_vtxt_issue_info(ofstream& outfile, const XMLElement* errors, const char* magic_number, map<string, int>& file_path_id) {
    cout<<"Output vtxt issue info"<<endl;
    const char* rule_id = "misra-xx";
    const char* file_path = NULL;
    int line_number = 0;
    int column_number = 0;
    for(const XMLElement* error = errors->FirstChildElement("error"); error != NULL; error = error->NextSiblingElement("error")) {
        outfile << "[" << magic_number <<"],";
        error->FirstChildElement("location")->QueryStringAttribute("file", &file_path);
        error->FirstChildElement("location")->QueryIntAttribute("line", &line_number);
        error->FirstChildElement("location")->QueryIntAttribute("column", &column_number);
        error->QueryStringAttribute("id", &rule_id);
        //cout << "[@" << Get_rule(rule_id) << "@" <<file_path_id.find(string(file_path))->second <<":"<< line_number <<"],"<< endl;
        outfile << "[@" << Get_rule(rule_id) << "@" 
            <<Get_filename(file_path) <<":"<< line_number
            <<"],[" << Get_filename(file_path) << "],["
            << file_path_id.find(string(file_path))->second
            <<":"<<line_number<<"],"
            <<"[SML],[D],[RBC],[1,0,0],[MSR],["
            <<Get_rule(rule_id)<<"],[],"<<"[],"
            <<"["<< file_path_id.find(string(file_path))->second
            <<":"<<line_number<<":"<<column_number
            <<":"<<"3]"<<endl;
    }
    cout<<"Output vtxt issue info end"<<endl;
}

int main(int argc, char* argv[]) {
    if(Cmd_option_exists(argv, argv+argc, "-h")) {
        cout<<"Usage: ./xml2vtxt -i input.xml -magic xxxx"<<endl;
        return 0;
    }

    char* magic_number = Get_cmd_option(argv, argv + argc, "-magic");
    if(!magic_number) {
        cout<<"missing magic parameter"<<endl;
        cout<<"Usage: ./xml2vtxt -i input.xml -magic xxxx"<<endl;
        exit(1);
    }

    char* xml_filename = Get_cmd_option(argv, argv + argc, "-i");
    if(!xml_filename) {
        cout<<"missing xml filename input"<<endl;
        cout<<"Usage: ./xml2vtxt -i input.xml -magic xxxx"<<endl;
        exit(1);
    }

    XMLDocument xml;
    if(xml.LoadFile(xml_filename) != XML_SUCCESS) {
        cout<<"parse xml file failed"<<endl;
        xml.PrintError();
        exit(1);
    }

    string output_filename(Remove_extension(xml_filename) + ".vtxt");
    ofstream outfile;
    outfile.open(output_filename);

    Output_vtxt_header(outfile, magic_number);

    const XMLElement* errors = xml.FirstChildElement("results")->FirstChildElement("errors");
    map<string, int> file_path_id;
    Output_vtxt_file_info(outfile, errors, file_path_id);
    Output_vtxt_issue_info(outfile, errors, magic_number, file_path_id);

    return 0;
}
