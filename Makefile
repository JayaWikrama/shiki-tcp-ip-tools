#
#	Makefile Info	: SHIKI_MAKE_FORMAT
#	ver         	: 1.01.19.12.19.16
#	author      	: Jaya Wikrama, S.T.
#	e-mail      	: jayawikrama89@gmail.com
#	Copyright (c) 2019 HANA,. Jaya Wikrama
#
#	1. Power full Makefile with separated object and executable file
#	2. Support for separated library directory
#	3. Auto generate for all structure directory
#	4. Save record for all history program
#
#	if you are using git, dont forget to run make init to ignore
#	BUILD_DIRECTORY and OBJ_DIRECTORY
#


CC = gcc
CFLAGS = -Wall
INCLUDE = -lssl -lcrypto
BUILD_DIRECTORY = build
OBJ_DIRECTORY = obj
SOURCE = tcp_test.c \
 shiki-tcp-ip-tools.c \
 ../shiki-time-tools/shiki-time-tools.c \
 ../shiki-linked-list/shiki-linked-list.c \
 ../shiki-json-tools/shiki-json-tools.c

OBJECTS = $(patsubst %.c,$(OBJ_DIRECTORY)/%.o,$(SOURCE))
OBJECTS_INTERNAL = $(subst ../,,$(OBJECTS))
TARGET = stcp
TIME_CREATED = `date +%y.%m.%d_%H.%M.%S`
GIT_IGNORE_CMD = `cat .gitignore | grep -v $(OBJ_DIRECTORY) | grep -v $(BUILD_DIRECTORY)`

ADDITION_OBJDIRPATH = $(OBJ_DIRECTORY)/shiki-time-tools \
 $(OBJ_DIRECTORY)/shiki-linked-list \
 $(OBJ_DIRECTORY)/shiki-json-tools

vpath $(TARGET) $(BUILD_DIRECTORY)
vpath %.o
vpath %.o $(OBJ_DIRECTORY)

$(TARGET): $(OBJECTS_INTERNAL)
	@echo
	@echo "  \033[1;33mCreating executable file : $@\033[0m"
	$(CC) $(CFLAGS) $(OBJECTS_INTERNAL) -o $(BUILD_DIRECTORY)/$@ $(INCLUDE)
	@cp $(BUILD_DIRECTORY)/$@ $(BUILD_DIRECTORY)/$@_$(TIME_CREATED)

$(OBJ_DIRECTORY)/%.o: %.c
	@echo
	@echo "  \033[1;32mCompiling: $<\033[0m"
	$(call init_proc);
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLUDE)

# complete compiling with external include source
with_external_lib: $(OBJECTS)
		@echo
		@echo "  \033[1;33mCreating executable file : $(TARGET)\033[0m"
		@$(CC) $(CFLAGS) `echo $(OBJECTS) | sed 's/\.\.\///g'` -o $(BUILD_DIRECTORY)/$(TARGET) $(INCLUDE)
		@cp $(BUILD_DIRECTORY)/$(TARGET) $(BUILD_DIRECTORY)/$(TARGET)_$(TIME_CREATED)

$(OBJ_DIRECTORY)/%.o: %.c
	@echo
	@echo "  \033[1;32mCompiling: $<\033[0m"
	$(call init_proc);
	@$(CC) $(CFLAGS) -c $< -o `echo $@ | sed 's/\.\.\///'` $(INCLUDE)

init:
	$(call init_proc);
	@echo "$(GIT_IGNORE_CMD)" > .gitignore
	@echo "$(OBJ_DIRECTORY)/" >> .gitignore
	@echo "$(BUILD_DIRECTORY)/" >> .gitignore

clean:
	@rm -fv `find . -type f -name '*.o'`
	@rm -fv ./$(BUILD_DIRECTORY)/$(TARGET)

define init_proc
	@mkdir -p $(OBJ_DIRECTORY)
	@mkdir -p $(BUILD_DIRECTORY)
	@mkdir -p $(ADDITION_OBJDIRPATH)
	@find . -type f -name '*.c' -printf '%h\n' |sort -u | grep -v '$(BUILD_DIRECTORY)' | grep -v '$(OBJ_DIRECTORY)' > dir.struct
	@cd $(OBJ_DIRECTORY) && xargs mkdir -p < ../dir.struct
endef