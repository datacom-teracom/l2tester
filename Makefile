SOURCE_FILES=$(shell ls src/l2t_*.cpp)
OBJS:=$(patsubst %.cpp, %.o, $(SOURCE_FILES))

BASEDIR=$(shell pwd)
BUILD_DIR=$(BASEDIR)/build
INCLUDE_DIR=$(BASEDIR)/include
SRC_DIR=$(BASEDIR)/src
CFLAGS+=-Wall -Werror -I$(INCLUDE_DIR) -fPIC -D__LINUX_ -std=c++11
LDFLAGS+=-lrt -lpthread

all:
	@echo "Execute 'make <target>' to compile l2tester to target language.";
	@echo ""
	@echo "Avaiable targets:"
	@echo "  cpp             :  Compile shared and static library."
	@echo "  lua             :  Compile lua module"
	@echo "  ruby            :  Compile ruby extension"
	@echo "  python          :  Compile python extension"
	@echo ""
	@echo "After, for Python and Ruby targets, it's possible to execute:"
	@echo "  'make dist' to create distributable."
	@echo "  'make install' to install as Python module or Ruby gem."
	@echo ""

doc:
	txt2tags -t html -o docs/l2tester.html docs/l2tester.t2t

# Clean project
clean:
	rm -f $(SRC_DIR)/*.o
	rm -f swig/*wrap*
	rm -rf $(BUILD_DIR)

# Create build directory
create_build_dir:
	mkdir -p $(BUILD_DIR);

# Compile objects
%.o: %.cpp
	g++ $(CFLAGS) -c -o $@ $<

#make cpp
CPP_EXAMPLES=$(patsubst examples/cpp/%.cpp, %, $(shell ls examples/cpp/*.cpp))
cpp: create_build_dir $(OBJS)
	g++ $(CFLAGS) -shared -o $(BUILD_DIR)/libl2tester.so $(OBJS)
	ar rcs $(BUILD_DIR)/libl2tester.a $(OBJS)
	$(foreach example,$(CPP_EXAMPLES),g++ $(CFLAGS) -o $(BUILD_DIR)/$(example) examples/cpp/$(example).cpp $(BUILD_DIR)/libl2tester.a $(LDFLAGS);)

#make lua
LUA_INCLUDE := -I$(LUA_PATH)
lua: lua_check lua_wrapper

lua_check:
ifndef LUA_PATH
	$(error Lua not found. You need to specify the LUA_PATH environment variable in order to compile the Lua wrappers. E.g. export LUA_PATH=/home/user/projects/lua/lua-5.2.3/src/)
endif


# make ruby
RUBY_INCLUDE := -I$(RUBY_PATH) -I$(RUBY_PATH)/x86_64-linux/

RUBY_BIN := $(shell readlink -f `which ruby`)
ruby: ruby_check ruby_wrapper

ruby_check:
ifndef RUBY_PATH
	$(error Ruby not found. You need to specify the RUBY_PATH environment variable in order to compile the Ruby wrappers. E.g. export RUBY_PATH=/home/user/.rbenv/versions/2.1.5/include/ruby-2.1.0/)
endif

# make python
PYTHON_INCLUDE := $(shell python-config --includes)
PYTHON_FLAGS := -threads
PYTHON_BIN := $(shell readlink -f `which python`)
python: python_wrapper
	mv $(BUILD_DIR)/l2tester.so $(BUILD_DIR)/_l2tester.so
	mv swig/l2tester.py $(BUILD_DIR)/l2tester.py

# Generic rule for swig wrappers
%_wrapper: create_build_dir $(OBJS)
	$(eval SWIG_INCLUDE := $($(shell echo $* | tr [:lower:] [:upper:])_INCLUDE))
	$(eval SWIG_FLAGS := $($(shell echo $* | tr [:lower:] [:upper:])_FLAGS))
	swig -$* $(SWIG_FLAGS) -c++ swig/l2tester.i
	g++ -c -std=c++11 swig/l2tester_wrap.cxx -I$(INCLUDE_DIR) -fPIC -D__LINUX_ -o swig/l2tester_wrap.o $(SWIG_INCLUDE)
	g++ -shared $(CFLAGS) -lrt -lpthread $(OBJS) swig/l2tester_wrap.o -o $(BUILD_DIR)/l2tester.so
	cp examples/$*/* build/
	echo "$*" > $(BUILD_DIR)/target

ifeq ($(shell cat $(BUILD_DIR)/target 2> /dev/null),python)

# Python module generation and installation
prepare_module:
	cp -R release/python/* $(BUILD_DIR)/
	cp $(BUILD_DIR)/_l2tester.so $(BUILD_DIR)/l2tester/
	cp $(BUILD_DIR)/l2tester.py $(BUILD_DIR)/l2tester/

dist: prepare_module
	cd $(BUILD_DIR); python setup.py sdist

install: prepare_module
	cd $(BUILD_DIR); sudo python setup.py install
	sudo setcap cap_mac_admin,cap_net_raw,cap_net_admin=eip $(PYTHON_BIN)

else ifeq ($(shell cat $(BUILD_DIR)/target 2> /dev/null),ruby)

# Ruby gem generation and installation
dist:
	cp release/ruby/l2tester.gemspec $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/lib
	cp $(BUILD_DIR)/l2tester.so $(BUILD_DIR)/lib/
	cd $(BUILD_DIR); gem build l2tester.gemspec

install: dist
	cd $(BUILD_DIR); sudo gem install l2tester-1.0.gem
	sudo setcap cap_mac_admin,cap_net_raw,cap_net_admin=eip $(RUBY_BIN)

else

dist:
	$(error Target not compiled or do not support distributable generation)
install:
	$(error Target not compiled or do not support installation)

endif
