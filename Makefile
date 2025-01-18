# Paths to the necessary directories
LIBPCAP_INCLUDE=libpcap-1.10.1                   # Path to the libpcap headers
LIBPCAP_LIB=./libpcap-1.10.1/lib                 # Corrected path to the libpcap library directory
LIBDBUS_LIB=./dbus-1.14.6/build/dbus             # Corrected path to the libdbus library directory

# Compiler and flags
CXX=g++
CXXFLAGS=-Wall -O2 -I$(LIBPCAP_INCLUDE)
LDFLAGS=-L$(LIBPCAP_LIB) -L$(LIBDBUS_LIB) -l:libpcap.a -l:libdbus-1.a -lsystemd

# Directories for your source and build files
SRCDIR   = .
BUILDDIR = build
BINDIR   = bin

# Project settings
TARGET  = $(BINDIR)/tracer
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(patsubst $(SRCDIR)/%.cpp, $(BUILDDIR)/%.o, $(SOURCES))

# Targets
all: $(TARGET)

$(TARGET): $(OBJECTS)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILDDIR) $(BINDIR)

.PHONY: all clean
