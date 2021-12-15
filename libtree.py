#!/usr/bin/env python

# usage
# python libtree.py /home/vanessa/Desktop/Code/spack-dev/opt/spack/linux-ubuntu20.04-skylake/gcc-9.3.0/jq-1.6-zigvwnfbtd3pyps5samyzsgsvqimavpc/lib/libjq.so

__author__ = "Vanessa Sochat"
__copyright__ = "Copyright 2021, Vanessa Sochat"
__license__ = "MPL 2.0"

# ASI automated software integration

import argparse
import sys
import os
from glob import glob

__version__ = "0.0.0"

try:
    import elftools
    from elftools.elf.elffile import ELFFile

except ImportError:
    sys.exit('pyelftools is required to read binaries.')


def get_parser():
    parser = argparse.ArgumentParser(
        description="Libtree Python",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # Copy the UI of libtree.c - there are no subparsers
    parser.add_argument(
        "libs",
        help="the name of the .so library to parse",
        nargs="+",
    )

    # Global Variables
    parser.add_argument(
        "--verbose",
        dest="verbose",
        help="use verbose logging to debug.",
        default=False,
        action="store_true",
    )

    parser.add_argument(
        "--version",
        dest="version",
        help="show software version.",
        default=False,
        action="store_true",
    )


    return parser

def read_file(filename):
    with open(filename, 'r') as fd:
        content = fd.read()
    return content


class CorpusReader(ELFFile):
    def __init__(self, filename):
        self.fd = open(filename, "rb")
        self.filename = filename
        try:
            self.elffile = ELFFile(self.fd)
        except:
            sys.exit("%s is not an ELF file." % filename)

    def __str__(self):
        return "[CorpusReader:%s]" % self.filename

    def __repr__(self):
        return str(self)

    @property
    def header(self):
        return dict(self.elffile.header)

    def __exit__(self):
        print("Closing reader")
        self.fd.close()

    def get_architecture(self):
        return self.elffile.header.get("e_machine")

    def get_elf_class(self):
        return self.elffile.elfclass



class Libtree:

    def __init__(self, paths, verbosity=0):

        # Enable or disable colors (no-color.com)
        self.color = os.environ.get("NO_COLOR") is None and sys.stdout.isatty()
        self.verbosity = verbosity
        
        # This should be a list of paths
        if not isinstance(paths, list):
            paths = [paths]
        self.paths = paths
        self._os_info = os.uname()
        self._state_init()
        # from .conf and LD_LIBRARY_PATH
        self.ld_paths = []

    @property
    def platform(self):
        # Technically this should be AT_PLATFORM, but
        # (a) the feature is rarely used
        # (b) it's almost always the same
        return self._os_info.machine

    def _state_init(self):

        # Keep track of visited nodes, etc.
        self.visited = set()

    @property
    def _visited_n(self):
        return len(self.visited)
        
    def lib(self):
        return self.path

    @property
    def osname(self):
        return self._os_info.sysname

    @property
    def osrel(self):
        return self._os_info.release

    def show_substitutions(self):
        print("\n\nThe following rpath/runpath substitutions are used:")    
        print("  PLATFORM       %s" % self.platform)
        print("  LIB       %s" % self.path)
        print("  OSNAME       %s" % self.osname)
        print("  OSREL       %s" % self.osrel)



    def parse_ld_so_conf(self):
        paths = []
        for filename in ["/etc/ld.so.conf", "/etc/ld-elf.so.conf"]:
            if os.path.exists(filename):
                paths += self._parse_ld_config_file(filename)
        return paths
        
    def _parse_ld_config_file(self, filename):
        """
        Recursively parse an ld config file
        """
        paths = []
        for line in read_file(filename).split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            if line.startswith("include"):
                line = line.replace('include', "").strip()
                for filename in glob(line):
                    paths += self._parse_ld_config_file(filename)
                continue
            # If we get here, append the line
            paths.append(line)
        return paths

    def parse_ld_library_path(self):
        """
        Get LD_LIBRARY_PATH from the environment
        """
        path = os.environ.get('LD_LIBRARY_PATH')
        if not path:
            return []
        return [x for x in path.split(':') if x]

    def set_default_paths(self):
        return ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]

    def parse(self):
        """Return a list of parsed paths
        """
        self.ld_paths += self.parse_ld_so_conf()
        self.ld_paths += self.parse_ld_library_path()
        self.ld_paths += self.set_default_paths()
          
    def print_tree(self):
        """
        Print a tree for the library
        """
        self.parse()
        self.recurse()

    def recurse(self):
        rpaths = []
        for path in self.paths:
            self.explore(path, rpaths)

    def explore(self, path, rpaths):
        """
        Explore
        """    
        corpus = CorpusReader(path)
        indent = self.get_indent()
# Not sure what is going on here (see README I don't understand the algorithm)
#        cached = self._visited
        import IPython
        IPython.embed()

    def get_indent(self):
        """   
std::string deps::get_indent(std::vector<bool> const &done) const {
    std::string indent;

    for (size_t idx = 0; idx + 1 < done.size(); ++idx)
        indent += done[idx] ? "    " : "│   ";
    
    if (done.size() != 0)
        indent += done.back() ? "└── " : "├── ";

    return indent;
}
        """
        return "    "


def main():
    parser = get_parser()

    # If an error occurs while parsing the arguments, the interpreter will exit with value 2
    args, extra = parser.parse_known_args()
    if args.version:
        sys.exit(__version__)

    if args.verbose:
        print('TODO verbosity')

    # Create and print a Libtree for each library 
    for lib in args.libs:
        tree = Libtree(lib)
        tree.print_tree()
    
    import IPython
    IPython.embed()

if __name__ == "__main__":
    main()
