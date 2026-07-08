/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#include "inspect.h"

#include "lief_loader.h"

#ifdef __APPLE__
  #include <mach-o/dyld.h>
#endif
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <algorithm>
#include <cxxabi.h>
#include <dwarf++.hh>

#include "util.h"

#include "ccutil/log.h"
#include "path_filter.h"

using namespace std;

static dwarf::value find_attribute(const dwarf::die& d, dwarf::DW_AT attr);

static string absolute_path(const string filename) {
  if(filename[0] == '/') return filename;

  char* cwd = getcwd(NULL, 0);
  REQUIRE(cwd != NULL) << "Failed to get current directory";

  return string(cwd) + '/' + filename;
}

static string canonicalize_path(const string filename) {
  vector<string> parts = split(absolute_path(filename), '/');

  // Iterate over the path parts to produce a reduced list of path sections
  vector<string> reduced;
  for(string part : parts) {
    if(part == "..") {
      REQUIRE(reduced.size() > 0) << "Invalid absolute path";
      reduced.pop_back();
    } else if(part.length() > 0 && part != ".") {
      // Skip single-dot or empty entries
      reduced.push_back(part);
    }
  }

  // Join path sections into a single string
  string result;
  for(string part : reduced) {
    result += "/" + part;
  }

  return result;
}

static bool file_exists(const string& filename) {
  struct stat statbuf;
  int rc = stat(filename.c_str(), &statbuf);
  // If the stat call succeeds, the file must exist
  return rc == 0;
}

/**
 * Get the full path to a file specified via absolute path, relative path, or raw name
 * resolved via the PATH variable.
 */
static const string get_full_path(const string filename) {
  if(filename.find('/') != string::npos) {
    return canonicalize_path(filename);

  } else {
    // Search the environment's path for the first match
    const string path_env = getenv("PATH");
    vector<string> search_dirs = split(getenv_safe("PATH", ":"));

    for(const string& dir : search_dirs) {
      string full_path = dir + '/' + filename;
      if(file_exists(full_path)) {
        return full_path;
      }
    }
  }

  return "";
}

#ifdef __APPLE__
unordered_map<string, uintptr_t> get_loaded_files() {
  unordered_map<string, uintptr_t> result;

  uint32_t count = _dyld_image_count();
  for(uint32_t i = 0; i < count; i++) {
    const char* name = _dyld_get_image_name(i);
    if(name && name[0] == '/') {
      intptr_t slide = _dyld_get_image_vmaddr_slide(i);
      result[name] = static_cast<uintptr_t>(slide);
    }
  }

  return result;
}
#else
unordered_map<string, uintptr_t> get_loaded_files() {
  unordered_map<string, uintptr_t> result;

  ifstream maps("/proc/self/maps");
  while(maps.good() && !maps.eof()) {
    uintptr_t base, limit;
    char perms[5];
    size_t offset;
    size_t dev_major, dev_minor;
    uintptr_t inode;
    string path;

    // Skip over whitespace
    maps >> skipws;

    // Read in "<base>-<limit> <perms> <offset> <dev_major>:<dev_minor> <inode>"
    maps >> std::hex >> base;
    if(maps.get() != '-') break;
    maps >> std::hex >> limit;

    if(maps.get() != ' ') break;
    maps.get(perms, 5);

    maps >> std::hex >> offset;
    maps >> std::hex >> dev_major;
    if(maps.get() != ':') break;
    maps >> std::hex >> dev_minor;
    maps >> std::dec >> inode;

    // Skip over spaces and tabs
    while(maps.peek() == ' ' || maps.peek() == '\t') { maps.ignore(1); }

    // Read out the mapped file's path
    getline(maps, path);

    // If this is an executable mapping of an absolute path, include it
    if(perms[2] == 'x' && path[0] == '/') {
      result[path] = base - offset;
    }
  }

  return result;
}
#endif

bool wildcard_match(string::const_iterator subject,
                    string::const_iterator subject_end,
                    string::const_iterator pattern,
                    string::const_iterator pattern_end) {

  if(pattern == pattern_end) {
    // No pattern left: matches only if subject is also fully consumed.
    return subject == subject_end;

  } else if(*pattern == '%') {
    // Try possible matches of the wildcard, starting with the longest
    // possible match. Checked before looking at whether subject is already
    // exhausted (unlike the other two branches below) because a trailing
    // '%' must be able to match zero remaining characters - e.g. matching
    // "%side_product%" against exactly "side_product", with nothing left
    // over for the trailing '%' to consume.
    for(auto match_end = subject_end; ; match_end--) {
      if(wildcard_match(match_end, subject_end, pattern+1, pattern_end)) {
        return true;
      }
      if(match_end == subject) break;
    }
    // No matches found. Abort
    return false;

  } else if(subject == subject_end) {
    // Pattern still has non-wildcard content left, but subject has none:
    // never a match.
    return false;

  } else {
    // Walk through non-wildcard characters to match
    while(subject != subject_end && pattern != pattern_end && *pattern != '%') {
      // If the characters do not match, abort. Otherwise keep going.
      if(*pattern != *subject) {
        return false;
      } else {
        pattern++;
        subject++;
      }
    }

    // Recursive call to handle wildcard or termination cases
    return wildcard_match(subject, subject_end, pattern, pattern_end);
  }
}

bool wildcard_match(const string& subject, const string& pattern) {
  return wildcard_match(subject.begin(), subject.end(), pattern.begin(), pattern.end());
}

static bool in_scope_normalized(const string& normalized,
                                const unordered_set<string>& scope) {
  for(const string& pattern : scope) {
    if(wildcard_match(normalized, pattern)) {
      return true;
    }
  }
  return false;
}

bool in_scope(const string& name, const unordered_set<string>& scope) {
  string normalized = canonicalize_path(name);
  return in_scope_normalized(normalized, scope);
}


static bool file_matches_scope(const string& name,
                               const unordered_set<string>& scope,
                               bool allow_system_sources) {
  if(name.empty())
    return false;
  string normalized = canonicalize_path(name);
  if(is_coz_header(normalized))
    return false;
  if(!allow_system_sources && is_system_path(normalized))
    return false;
  if(scope.empty())
    return true;
  // Filter Rust toolchain/dependency paths unless user specified an explicit source scope
  bool default_scope = (scope.size() == 1 && scope.count("%") == 1);
  if(default_scope && is_rust_path(normalized))
    return false;
  return in_scope_normalized(normalized, scope);
}

static void enqueue_range(vector<memory_map::queued_range>& pending,
                          const string& filename,
                          size_t line_no,
                          interval range,
                          bool preferred = false) {
  if(filename.empty())
    return;
  pending.push_back(memory_map::queued_range{filename, line_no, range, preferred});
}

struct subprogram_range {
  uintptr_t low;
  uintptr_t high;
  std::string filename;
  size_t line;
  bool in_scope;
  // Only set on the first range pushed for a given subprogram DIE (relevant
  // when DW_AT::ranges reports several disjoint blocks, e.g. cold-path
  // splitting at -O2+) - so a --fixed-symbol lookup registers one entry per
  // function, not one per address range.
  std::string symbol_name;
  // The demangled "Class::method" (or "func<T>") form, when DW_AT::linkage_name
  // is present and differs from symbol_name - lets --fixed-symbol disambiguate
  // overloads/overrides/template instantiations that all share the same plain
  // name. Empty when there's nothing more specific than symbol_name to offer
  // (e.g. extern "C" functions, which usually have no mangled linkage name).
  std::string qualified_name;
};

// Demangled C++ names look like "Namespace::Class::method(int, float) const".
// Cut at the function's own parameter list (the first '(' at paren/template
// nesting depth 0) so --fixed-symbol users can type "Class::method" instead
// of the full signature. Left as symbol_name-equivalent if demangling fails
// or the mangled form doesn't look like a function signature at all.
static string extract_qualified_name(const string& demangled) {
  int depth = 0;
  for(size_t i = 0; i < demangled.size(); i++) {
    char c = demangled[i];
    if(c == '(' && depth == 0) {
      return demangled.substr(0, i);
    }
    if(c == '<' || c == '(') depth++;
    else if(c == '>' || c == ')') depth--;
  }
  return demangled;
}

static void collect_subprogram_ranges(const dwarf::die& d,
                                      const dwarf::line_table& table,
                                      const unordered_set<string>& source_scope,
                                      bool allow_system_sources,
                                      vector<subprogram_range>& ranges) {
  if(!d.valid())
    return;

  try {
    if(d.tag == dwarf::DW_TAG::subprogram) {
      string decl_file;
      dwarf::value decl_file_val = find_attribute(d, dwarf::DW_AT::decl_file);
      // GCC/DWARF5 often encodes this as a fixed-width data1/data2/data4/data8
      // form, which this libelfin fork classifies as the generic `constant`
      // type, not `uconstant` - as_uconstant() handles both forms identically,
      // so accept either type tag rather than silently dropping decl_file.
      if(decl_file_val.valid() &&
         (decl_file_val.get_type() == dwarf::value::type::uconstant ||
          decl_file_val.get_type() == dwarf::value::type::constant) &&
         table.valid()) {
        decl_file = table.get_file(decl_file_val.as_uconstant())->path;
        decl_file = canonicalize_path(decl_file);
      }
      size_t decl_line = 0;
      dwarf::value decl_line_val = find_attribute(d, dwarf::DW_AT::decl_line);
      if(decl_line_val.valid()) {
        if(decl_line_val.get_type() == dwarf::value::type::uconstant ||
           decl_line_val.get_type() == dwarf::value::type::constant)
          decl_line = decl_line_val.as_uconstant();
        else if(decl_line_val.get_type() == dwarf::value::type::sconstant)
          decl_line = decl_line_val.as_sconstant();
      }

      // Used for --fixed-symbol lookup: the plain (unqualified) name - fine
      // on its own for extern "C" functions, but overloaded/overridden C++
      // methods and template instantiations all share the same one, so
      // they're ambiguous under this key alone (qualified_name below
      // disambiguates those).
      string symbol_name;
      dwarf::value name_val = find_attribute(d, dwarf::DW_AT::name);
      if(name_val.valid() && name_val.get_type() == dwarf::value::type::string) {
        symbol_name = name_val.as_string();
      }

      // The demangled "Class::method"/"func<T>" form, when linkage_name
      // (the mangled symbol) is present and demangles to something more
      // specific than symbol_name.
      string qualified_name;
      dwarf::value linkage_name_val = find_attribute(d, dwarf::DW_AT::linkage_name);
      if(linkage_name_val.valid() && linkage_name_val.get_type() == dwarf::value::type::string) {
        string mangled = linkage_name_val.as_string();
        int status = 0;
        char* demangled = abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);
        if(status == 0 && demangled != nullptr) {
          string extracted = extract_qualified_name(string(demangled));
          if(extracted != symbol_name) qualified_name = extracted;
        }
        free(demangled);
      }

      bool file_in_scope = decl_file.size() > 0 &&
                           file_matches_scope(decl_file, source_scope, allow_system_sources);

      if(file_in_scope && decl_line > 0) {
        dwarf::value ranges_val = find_attribute(d, dwarf::DW_AT::ranges);
        if(ranges_val.valid()) {
          bool first = true;
          for(auto r : ranges_val.as_rangelist()) {
            ranges.push_back(subprogram_range{r.low, r.high, decl_file, decl_line, true,
                                              first ? symbol_name : string(),
                                              first ? qualified_name : string()});
            first = false;
          }
        } else {
          dwarf::value low_pc_val = find_attribute(d, dwarf::DW_AT::low_pc);
          dwarf::value high_pc_val = find_attribute(d, dwarf::DW_AT::high_pc);
          if(low_pc_val.valid() && high_pc_val.valid()) {
            uintptr_t low_pc = 0;
            uintptr_t high_pc = 0;

            if(low_pc_val.get_type() == dwarf::value::type::address)
              low_pc = low_pc_val.as_address();
            else if(low_pc_val.get_type() == dwarf::value::type::uconstant ||
                    low_pc_val.get_type() == dwarf::value::type::constant)
              low_pc = low_pc_val.as_uconstant();
            else if(low_pc_val.get_type() == dwarf::value::type::sconstant)
              low_pc = low_pc_val.as_sconstant();

            // DWARF4+: when high_pc's form class is "address", it's an
            // absolute address; otherwise (commonly a fixed-width data1/2/4/8
            // form, classified here as `constant` rather than `uconstant`)
            // it's an offset *from* low_pc, not an absolute value on its own.
            if(high_pc_val.get_type() == dwarf::value::type::address)
              high_pc = high_pc_val.as_address();
            else if(high_pc_val.get_type() == dwarf::value::type::uconstant ||
                    high_pc_val.get_type() == dwarf::value::type::constant)
              high_pc = low_pc + high_pc_val.as_uconstant();
            else if(high_pc_val.get_type() == dwarf::value::type::sconstant)
              high_pc = low_pc + high_pc_val.as_sconstant();

            if(high_pc > low_pc) {
              ranges.push_back(subprogram_range{low_pc, high_pc, decl_file, decl_line, true,
                                                symbol_name, qualified_name});
            }
          }
        }
      }
    }
  } catch(dwarf::format_error e) {
    (void)e;
  }

  for(const auto& child : d) {
    collect_subprogram_ranges(child, table, source_scope, allow_system_sources, ranges);
  }
}

static const subprogram_range* find_subprogram(const vector<subprogram_range>& ranges,
                                               uintptr_t addr) {
  if(ranges.empty())
    return nullptr;

  auto it = upper_bound(ranges.begin(),
                        ranges.end(),
                        addr,
                        [](uintptr_t value, const subprogram_range& range) {
                          return value < range.low;
                        });
  if(it == ranges.begin())
    return nullptr;

  --it;
  if(addr >= it->low && addr < it->high)
    return &(*it);
  return nullptr;
}

size_t memory_map::scan_new_binaries(const string& force_include_path) {
  auto loaded = get_loaded_files();

  string force_include_canonical;
  if(_auto_scope && !force_include_path.empty()) {
    force_include_canonical = canonicalize_path(force_include_path);
  }

  size_t in_scope_count = 0;
  for(const auto& f : loaded) {
    const string& path = f.first;
    if(_processed_binaries.count(path) > 0) continue;

    // auto_scope lets a library the caller explicitly dlopen'd bypass
    // binary_scope entirely - the dlopen() call itself is the signal that
    // this binary is wanted. Anything else newly mapped in this same
    // snapshot (e.g. a transitive dependency pulled in alongside it) still
    // has to match binary_scope normally.
    bool forced = !force_include_canonical.empty() &&
                  canonicalize_path(path) == force_include_canonical;
    if(!forced && !in_scope(path, _binary_scope)) continue;

    // Mark as attempted before processing so a later rescan() never retries
    // a binary that failed or had no debug info, matching build()'s existing
    // one-shot-per-binary semantics.
    _processed_binaries.insert(path);

    try {
      if(process_file(path, f.second, _source_scope, _allow_system_sources)) {
        VERBOSE << "Including lines from executable " << path;
        in_scope_count++;
      } else {
        VERBOSE << "Unable to locate debug information for " << path;
      }
    } catch(const std::exception& e) {
      // Catch broadly, not just system_error: a single library with
      // malformed or unsupported debug info (more likely now that
      // auto_scope/'%' pull in a wider, less-curated set of binaries) must
      // not take down the whole profiled process.
      WARNING << "Processing file \"" << path << "\" failed: " << e.what();
    }
  }
  return in_scope_count;
}

void memory_map::build(const unordered_set<string>& binary_scope,
                       const unordered_set<string>& source_scope,
                       bool allow_system_sources,
                       bool auto_scope) {
  _binary_scope = binary_scope;
  _source_scope = source_scope;
  _allow_system_sources = allow_system_sources;
  _auto_scope = auto_scope;

  size_t in_scope_count = scan_new_binaries();

  // This used to be a fatal REQUIRE, but zero in-scope binaries at bootstrap
  // is now an expected state: a scope pattern may only match libraries that
  // are dlopen'd later (that's the whole point of the incremental rescan
  // path), so failing to find anything yet must not abort the process.
  if(in_scope_count == 0) {
    WARNING << "Debug information was not found for any in-scope executables "
            << "or libraries yet; will rescan as libraries are dlopen'd";
  }
}

void memory_map::rescan(const string& force_include_path) {
  _lock.lock();
  size_t newly_processed = scan_new_binaries(force_include_path);
  _lock.unlock();

  if(newly_processed > 0) {
    VERBOSE << "Rescan added debug info for " << newly_processed
            << " newly-loaded binaries";
  }
  // No REQUIRE here: finding zero newly-in-scope binaries is the common,
  // expected case (e.g. a dlopen'd library that doesn't match binary_scope)
  // and must not abort the process.
}

dwarf::value find_attribute(const dwarf::die& d, dwarf::DW_AT attr) {
  if(!d.valid())
    return dwarf::value();

  try {
    if(d.has(attr))
      return d[attr];

    if(d.has(dwarf::DW_AT::abstract_origin)) {
      const dwarf::die child = d.resolve(dwarf::DW_AT::abstract_origin).as_reference();
      dwarf::value v = find_attribute(child, attr);
      if(v.valid())
        return v;
    }

    if(d.has(dwarf::DW_AT::specification)) {
      const dwarf::die child = d.resolve(dwarf::DW_AT::specification).as_reference();
      dwarf::value v = find_attribute(child, attr);
      if(v.valid())
        return v;
    }
  } catch(dwarf::format_error e) {
    (void)e;
  }

  return dwarf::value();
}

void memory_map::add_range(std::string filename, size_t line_no, interval range) {
  shared_ptr<file> f = get_file(filename);
  shared_ptr<line> l = f->get_line(line_no);
  // Add the entry
  _ranges.emplace(range, l);
}

void memory_map::process_inlines(const dwarf::die& d,
                                 const dwarf::line_table& table,
                                 const unordered_set<string>& source_scope,
                                 uintptr_t load_address,
                                 bool allow_system_sources,
                                 vector<memory_map::queued_range>& pending,
                                 const string& parent_file,
                                 size_t parent_line,
                                 bool parent_in_scope) {
  if(!d.valid())
    return;

  string attribution_file = parent_file;
  size_t attribution_line = parent_line;
  bool attribution_valid = parent_in_scope && !parent_file.empty();

  try {
    if(d.tag == dwarf::DW_TAG::inlined_subroutine) {
      string call_file;
      if(d.has(dwarf::DW_AT::call_file) && table.valid()) {
        call_file = table.get_file(d[dwarf::DW_AT::call_file].as_uconstant())->path;
        call_file = canonicalize_path(call_file);
      }

      size_t call_line = 0;
      if(d.has(dwarf::DW_AT::call_line)) {
        call_line = d[dwarf::DW_AT::call_line].as_uconstant();
      }

      bool call_in_scope = file_matches_scope(call_file, source_scope, allow_system_sources);
      bool prefer_new_attribution = !attribution_valid || !is_system_path(call_file);
      if(call_in_scope && !call_file.empty() && prefer_new_attribution) {
        attribution_file = call_file;
        attribution_line = call_line;
        attribution_valid = true;
      }

      if(attribution_valid) {
        dwarf::value ranges_val = find_attribute(d, dwarf::DW_AT::ranges);
        if(ranges_val.valid()) {
          for(auto r : ranges_val.as_rangelist()) {
            enqueue_range(pending,
                          attribution_file,
                          attribution_line,
                          interval(r.low, r.high) + load_address,
                          /*preferred=*/true);
          }
        } else {
          dwarf::value low_pc_val = find_attribute(d, dwarf::DW_AT::low_pc);
          dwarf::value high_pc_val = find_attribute(d, dwarf::DW_AT::high_pc);

          if(low_pc_val.valid() && high_pc_val.valid()) {
            uint64_t low_pc = 0;
            uint64_t high_pc = 0;

            if(low_pc_val.get_type() == dwarf::value::type::address)
              low_pc = low_pc_val.as_address();
            else if(low_pc_val.get_type() == dwarf::value::type::uconstant)
              low_pc = low_pc_val.as_uconstant();
            else if(low_pc_val.get_type() == dwarf::value::type::sconstant)
              low_pc = low_pc_val.as_sconstant();

            if(high_pc_val.get_type() == dwarf::value::type::address)
              high_pc = high_pc_val.as_address();
            else if(high_pc_val.get_type() == dwarf::value::type::uconstant)
              high_pc = high_pc_val.as_uconstant();
            else if(high_pc_val.get_type() == dwarf::value::type::sconstant)
              high_pc = high_pc_val.as_sconstant();

            if(high_pc > low_pc) {
              enqueue_range(pending,
                            attribution_file,
                            attribution_line,
                            interval(low_pc, high_pc) + load_address,
                            /*preferred=*/true);
            }
          }
        }
      }

      for(const auto& child : d) {
        process_inlines(child,
                        table,
                        source_scope,
                        load_address,
                        allow_system_sources,
                        pending,
                        attribution_file,
                        attribution_line,
                        attribution_valid);
      }
      return;
    }
  } catch(dwarf::format_error e) {
    (void)e;
  }

  for(const auto& child : d) {
    process_inlines(child,
                    table,
                    source_scope,
                    load_address,
                    allow_system_sources,
                    pending,
                    attribution_file,
                    attribution_line,
                    attribution_valid);
  }
}

bool memory_map::process_file(const string& name, uintptr_t load_address,
                              const unordered_set<string>& source_scope,
                              bool allow_system_sources) {
  // Use unified LIEF-based loader for both ELF and Mach-O
  auto loader = lief_loader::load(name);
  if(!loader) {
    return false;
  }
  dwarf::dwarf d(loader);

#ifndef __APPLE__
  // On Linux, adjust load_address for static executables (ET_EXEC)
  // Static executables are loaded at fixed addresses (typically 0)
  // PIE executables and shared libraries (ET_DYN) use the load address from /proc/self/maps
  if(lief_loader::is_static_executable(name)) {
    load_address = 0;
  }
#endif
  // On macOS, load_address is already the ASLR slide from dyld

  vector<memory_map::queued_range> pending;

  // Named subprograms collected across every CU in this file, resolved to
  // candidate lines and registered into _symbols after _ranges is populated
  // below (find_line(addr) needs this file's ranges to already be present).
  vector<subprogram_range> named_subprograms;

  // Walk through the compilation units (source files) in the executable
  for(auto unit : d.compilation_units()) {

    try {
      string prev_filename;
      size_t prev_line;
      uintptr_t prev_address = 0;
      set<string> included_files;
      dwarf::line_table table;
#ifdef __APPLE__
      // On macOS, catch DWARF parsing errors and skip problematic CUs
      try {
        table = unit.get_line_table();
      } catch (const dwarf::format_error& e) {
        continue;
      } catch (const std::exception& e) {
        continue;
      }
#else
      // On Linux, let DWARF parsing exceptions propagate for proper error reporting
      table = unit.get_line_table();
#endif
      if(!table.valid()) {
        continue;
      }
      vector<subprogram_range> subprograms;
      collect_subprogram_ranges(unit.root(),
                                table,
                                source_scope,
                                allow_system_sources,
                                subprograms);
      sort(subprograms.begin(), subprograms.end(),
           [](const subprogram_range& a, const subprogram_range& b) {
             if(a.low != b.low)
               return a.low < b.low;
             return a.high < b.high;
           });

      for(const auto& s : subprograms) {
        if(!s.symbol_name.empty()) named_subprograms.push_back(s);
      }

      // Walk through the line instructions in the DWARF line table
      for(auto& line_info : table) {
        // Insert an entry if this isn't the first line command in the sequence
        if(file_matches_scope(prev_filename, source_scope, allow_system_sources)) {
          if(prev_address != 0) {
            const subprogram_range* owner = find_subprogram(subprograms, prev_address);
            if(owner && owner->in_scope) {
              bool owner_is_system = is_system_path(owner->filename);
              bool prev_is_system = is_system_path(prev_filename);
              if(prev_is_system && !owner_is_system) {
                prev_filename = owner->filename;
                prev_line = owner->line;
              }
            }
          }
          if(prev_address != 0) {
            included_files.insert(prev_filename);
            enqueue_range(pending,
                          prev_filename,
                          prev_line,
                          interval(prev_address, line_info.address) + load_address);
          }
        }

        if(line_info.end_sequence || line_info.line == 0) {
          prev_address = 0;
        } else {
          prev_filename = canonicalize_path(line_info.file->path);
          prev_line = line_info.line;
          prev_address = line_info.address;
        }
      }
      process_inlines(unit.root(),
                      table,
                      source_scope,
                      load_address,
                      allow_system_sources,
                      pending);

      for(const string& filename : included_files) {
        VERBOSE << "Included source file " << filename;
      }

    } catch(dwarf::format_error e) {
      (void)e;
    }
  }

  std::sort(pending.begin(), pending.end(),
            [](const memory_map::queued_range& a, const memory_map::queued_range& b) {
              if(a.range.get_base() != b.range.get_base())
                return a.range.get_base() < b.range.get_base();
              if(a.range.get_limit() != b.range.get_limit())
                return a.range.get_limit() < b.range.get_limit();
              if(a.preferred != b.preferred)
                return a.preferred && !b.preferred;
              if(a.line != b.line)
                return a.line < b.line;
              return a.filename < b.filename;
            });
  for(auto& entry : pending) {
    add_range(entry.filename, entry.line, entry.range);
  }

  // Register --fixed-symbol targets now that _ranges has this file's data.
  // One entry per (symbol name, binary) pair - collect_subprogram_ranges()
  // already ensures at most one named subprogram_range per function even
  // when DW_AT::ranges reports several disjoint address blocks.
  for(const auto& s : named_subprograms) {
    uintptr_t entry_addr = s.low + load_address;
    uintptr_t end_addr = s.high + load_address;
    shared_ptr<line> entry_line = find_line(entry_addr);
    shared_ptr<line> resolved = entry_line;

    // Prefer whichever line within the function has the most address-range
    // entries, rather than just the entry/prologue line or the next line in
    // program order. A function's first instruction's line is almost always
    // its own declaration/signature line (prologue), and the statement right
    // after it is often just a one-time initializer - neither accumulates
    // real samples, since both execute once per call in a handful of cycles.
    // A line the compiler emitted multiple address ranges for is a strong
    // proxy for "this is a loop body the CPU actually revisits repeatedly",
    // which is what makes a good --fixed-symbol target in practice.
    if(entry_line) {
      unordered_map<line*, size_t> counts;
      unordered_map<line*, shared_ptr<line>> owners;
      auto it = _ranges.find(entry_addr);
      while(it != _ranges.end() && it->first.get_base() < end_addr) {
        counts[it->second.get()]++;
        owners[it->second.get()] = it->second;
        ++it;
      }
      line* best = nullptr;
      size_t best_count = 0;
      for(const auto& entry : counts) {
        if(entry.second > best_count) {
          best_count = entry.second;
          best = entry.first;
        }
      }
      if(best && best_count > 1) {
        resolved = owners[best];
      }
      // Kept permanently (not a throwaway debug print) so --fixed-symbol's
      // line-selection heuristic is inspectable via COZ_VERBOSE=1 instead of
      // needing print statements added back in every time it's in question.
      VERBOSE << "Symbol \"" << s.symbol_name << "\" [0x" << std::hex << entry_addr
              << ", 0x" << end_addr << std::dec << "): entry line was "
              << (entry_line ? entry_line->get_line() : 0) << ", picked line "
              << (resolved ? resolved->get_line() : 0) << " with " << best_count
              << " address-range entries, out of " << counts.size()
              << " distinct candidate line(s):";
      for(const auto& entry : counts) {
        VERBOSE << "  line " << entry.first->get_line() << ": " << entry.second << " entries";
      }
    }

    if(resolved) {
      _symbols[s.symbol_name].push_back(symbol_match{name, resolved});
      // Also register under the demangled "Class::method"/"func<T>" form
      // (when one exists and actually differs from symbol_name), so
      // --fixed-symbol can disambiguate overloads/overrides/template
      // instantiations that all share the same plain name.
      if(!s.qualified_name.empty()) {
        _symbols[s.qualified_name].push_back(symbol_match{name, resolved});
      }
    }
  }

  return true;
}

shared_ptr<line> memory_map::find_line(const string& name) {
  string::size_type colon_pos = name.find_first_of(':');
  if(colon_pos == string::npos) {
    WARNING << "Could not identify file name in input " << name;
    return shared_ptr<line>();
  }

  string filename = name.substr(0, colon_pos);
  string line_no_str = name.substr(colon_pos + 1);

  size_t line_no;
  stringstream(line_no_str) >> line_no;

  for(const auto& f : files()) {
    string::size_type last_pos = f.first.rfind(filename);
    if(last_pos != string::npos && last_pos + filename.size() == f.first.size()) {
      if(f.second->has_line(line_no)) {
        return f.second->get_line(line_no);
      }
    }
  }

  return shared_ptr<line>();
}

shared_ptr<line> memory_map::find_line(uintptr_t addr) {
  auto iter = _ranges.find(addr);
  if(iter != _ranges.end()) {
    return iter->second;
  } else {
    return shared_ptr<line>();
  }
}

vector<memory_map::symbol_match> memory_map::find_symbol(const string& symbol_name,
                                                          const string& binary_pattern) const {
  vector<symbol_match> result;

  // A '%' in the name means "match every registered symbol name against
  // this pattern" (same wildcard convention as --binary-scope/--source-
  // scope), rather than the exact-match fast path below. This is a linear
  // scan over every distinct name ever registered - fine here, since it
  // only runs once per rescan (a dlopen call), never on the sampling path.
  vector<const vector<symbol_match>*> matched_name_groups;
  if(symbol_name.find('%') != string::npos) {
    for(const auto& entry : _symbols) {
      if(wildcard_match(entry.first, symbol_name)) {
        matched_name_groups.push_back(&entry.second);
      }
    }
  } else {
    auto it = _symbols.find(symbol_name);
    if(it == _symbols.end()) return result;
    matched_name_groups.push_back(&it->second);
  }

  if(binary_pattern.empty()) {
    for(const auto* group : matched_name_groups) {
      result.insert(result.end(), group->begin(), group->end());
    }
    return result;
  }

  // A pattern with no wildcard is treated as a suffix match - "libfoo.so"
  // should work without the caller needing to know/type the full path.
  string pattern = binary_pattern;
  if(pattern.find('%') == string::npos) {
    pattern = "%" + pattern;
  }
  unordered_set<string> scope{pattern};

  for(const auto* group : matched_name_groups) {
    for(const auto& match : *group) {
      if(in_scope(match.binary_path, scope)) {
        result.push_back(match);
      }
    }
  }
  return result;
}

memory_map& memory_map::get_instance() {
  static char buf[sizeof(memory_map)];
  static memory_map* the_instance = new(buf) memory_map();
  return *the_instance;
}
