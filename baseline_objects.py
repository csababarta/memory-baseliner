#import binascii
import io
import json
import logging
import pefile
import uuid
from urllib import request
from volatility3 import framework, plugins
from volatility3.cli import PrintedProgress

class BaselineProcess(object):
    """BaselineProcess class

    This class describes a process object with the properties used during the
    comparison process.
    """

    def __init__(self):
        """__init__

        Constructor
        """
        self.logger = logging.getLogger('BaselineProcess')
        self.logger.debug('__INIT__ called')

        self.uuid = ''
        self.pid = -1
        self.ppid = -1
        self.process_name = ''
        self.process_cmd_line = ''
        self.process_imphash = ''
        self.process_owner = ''

        self.parent_uuid = ''
        self.parent = None

        self.dlls = []

    @property
    def uuid(self) -> str:
        """uuid property getter

        Returns a string stored in the internal __uuid field
        It is used to identify the process when it's exported to JSON
        """
        self.logger.debug('UUID property getter called')

        return self.__uuid

    @uuid.setter
    def uuid(self,
             uuid: str):
        """uuid property setter

        Sets the internal __uuid field
        """
        self.logger.debug('UUID property setter called')

        self.__uuid = uuid

    @property
    def pid(self) -> int:
        """pid property getter

        Returns integer stored the internal __pid field
        Represents the process ID of the process from the EPROCESS structure
        """
        self.logger.debug('PID property getter called')

        return self.__pid

    @pid.setter
    def pid(self,
            pid: int):
        """pid property setter

        Sets the internal __pid field
        """
        self.logger.debug('PID property setter called')

        self.__pid = pid

    @property
    def ppid(self) -> int:
        """ppid property getter

        Returns integer stored the internal __ppid field
        Represents the process ID of the parent process as stored in the
          EPROCESS structure
        """
        self.logger.debug('PPID property getter called')

        return self.__ppid

    @ppid.setter
    def ppid(self,
             ppid: int):
        """ppid property setter

        Sets the internal __ppid field
        """
        self.logger.debug('PPID property setter called')

        self.__ppid = ppid

    @property
    def process_name(self) -> str:
        """process_name property getter

        Returns string stored the internal __process_name field
        Represents the process name of the process as stored in the EPROCESS
          structure
        """
        self.logger.debug('PROCESS_NAME property getter called')

        return self.__process_name

    @process_name.setter
    def process_name(self,
                     process_name: str):
        """process_name property setter

        Sets the internal __process_name field
        """
        self.logger.debug('PROCESS_NAME property setter called')

        self.__process_name = process_name

    @property
    def process_cmd_line(self) -> str:
        """process_cmd_line property getter

        Returns string stored in the internal __process_cmd_line field
        Represents the command line used to start the process as stored in the
          PEB structure
        """
        self.logger.debug('PROCESS_CMD_LINE property getter called')

        return self.__process_cmd_line

    @process_cmd_line.setter
    def process_cmd_line(self,
                         process_cmd_line: str):
        """process_cmd_line property setter

        Sets the internal __process_cmd_line field
        """
        self.logger.debug('PROCESS_CMD_LINE property setter called')

        self.__process_cmd_line = process_cmd_line

    @property
    def process_imphash(self) -> str:
        """process_imphash property getter

        Returns string with the import hash value stored in the internal field
          __process_imphash
        """
        self.logger.debug('PROCESS_IMPHASH property getter called')

        return self.__process_imphash

    @process_imphash.setter
    def process_imphash(self,
               imphash: str):
        """process_imphash property setter

        Sets the internal __process_imphash field
        """
        self.logger.debug('PROCESS_IMPHASH property setter called')

        self.__process_imphash = imphash

    @property
    def parent(self) -> object:
        """parent property getter

        Returns the parent BaselineProcess object from the internal __parent
          field
        """
        self.logger.debug('PARENT property getter called')

        return self.__parent

    @parent.setter
    def parent(self,
               parent: object):
        """parent property getter

        Sets the internal __parent with a BaselineProcess object
          field
        """
        self.logger.debug('PARENT property setter called')

        self.__parent = parent

    @property
    def parent_uuid(self) -> str:
        """parent_uuid property getter

        Returns string with the UUID of the parent BaselineProcess object from
          the internal parent_uuid field
        This UUID identifies the parent process in the JSON export
        """
        self.logger.debug('PARENT_UUID property getter called')

        return self.__parent_uuid

    @parent_uuid.setter
    def parent_uuid(self,
               parent_uuid: str):
        """parent_uuid property setter

        Sets the internal parent_uuid field
        """
        self.logger.debug('PARENT_UUID property setter called')

        self.__parent_uuid = parent_uuid

    def is_same_as(self,
                   process: object,
                   compare_imphash: bool,
                   compare_owner: bool,
                   compare_cmdline: bool) -> bool:
        """is_same_as

        This function is responsible for comparing two BaselineProcess objects.
        Returns
          boolean

        Input
          process: BaselineProcess object
          compare_imphash: boolean /also compare import hashes/
          compare_owner: boolean /also compare process owners/
          compare_cmdline: boolean /also compare command lines/
        """
        self.logger.debug('IS_SAME_AS called')

        # Compare processes
        same_name = self.process_name.lower() == process.process_name.lower()
        same_cmd_line = self.process_cmd_line.lower() == process.process_cmd_line.lower()
        same_imphash = self.process_imphash == process.process_imphash
        same_owner = self.process_owner == process.process_owner

        same_parent = False
        if self.parent != None and process.parent != None:
            same_parent = self.parent.process_name.lower() == process.parent.process_name.lower()
        elif self.parent == None and process.parent == None:
            same_parent = True
        else:
            same_parent = False

        result = same_name and same_parent

        if compare_cmdline:
            result = result and same_cmd_line

        if compare_owner:
            result = result and same_owner

        if compare_imphash:
            result = result and same_imphash

        return result

    def from_process(self,
                     process: object,
                     context: framework.interfaces.context.ContextInterface):
        """from_process

        This function is responsible for loading the content of a BaselineProcess
          object from a process object returned by the Volatility framework and
          filling in the internal fields with it.

        Input
          process: Volatility EPROCESS object
          context: Volatility context object
        """
        self.logger.debug('FROM_PROCESS called')

        # sanity checks
        if not isinstance(process.UniqueProcessId, int):
            self.logger.error('PID must be an instance of "int"!')
            raise Exception('PID must be an instance of "int"!')

        if process.UniqueProcessId <= 0:
            self.logger.error('PID must be greater than 0!')
            raise Exception('PID must be greater than 0!')

        self.uuid = str(uuid.uuid4())
        self.pid = process.UniqueProcessId
        self.ppid = process.InheritedFromUniqueProcessId
        try:
            self.process_name = process.ImageFileName.cast("string",
                                                           max_length = process.ImageFileName.vol.count,
                                                           errors = 'replace')
        except Exception as e:
            self.logger.error('Process name could not be determined! (%d)(%s)(%s)' % (self.pid, type(e).__name__, str(e)))
            raise Exception('Process name could not be determined! (%d)(%s)(%s)' % (self.pid, type(e).__name__, str(e)))


        self.process_cmd_line = self.get_cmd_line(process = process,
                                                  context = context)

        try:
            self.process_owner = process.Token.dereference().cast("_TOKEN").LogonSession.dereference().cast('_SEP_LOGON_SESSION_REFERENCES').AccountName.get_string()
        except Exception as e:
            self.logger.warning('Process owner could not be determined! (%d)(%s)(%s)' % (self.pid, type(e).__name__, str(e)))
            self.process_owner = ''

        self.parent = None


        try:
            peobj = pefile.PE(data = self.dump_pe(process = process,
                                                  context = context,
                                                  process_layer_name = process.add_process_layer()).read())
            try:
                self.process_imphash = peobj.get_imphash()
            except Exception as f:
                self.logger.warning('Process imphash could not be calculated! (%d)(%s)(%s)' % (self.pid, type(f).__name__, str(f)))
                self.process_imphash = ''
        except Exception as e:
            self.logger.warning('Process PE object could not be created! (%d)(%s)(%s)' % (self.pid, type(e).__name__, str(e)))
            self.process_imphash = ''

        self.dlls = self.get_dlls(process = process,
                                  context = context)
        self.children = []

    def to_dict(self) -> dict:
        """to_dict

        This function is responsible for exporting a BaselineProcess object into
          a dictionary.

        Returns
          dict
        """
        self.logger.debug('TO_DICT called')

        return {
            'uuid': self.uuid,
            'pid': self.pid,
            'ppid': self.ppid,
            'process_name': self.process_name,
            'process_cmd_line': self.process_cmd_line,
            'process_imphash': self.process_imphash,
            'process_owner': self.process_owner,
            'parent_uuid': self.parent.uuid if self.parent != None else '',
            'dlls': [dll.to_dict() for dll in self.dlls]
        }

    def from_dict(self,
                  entry: dict):
        """from_dict

        This function is responsible for loading the content of a BaselineProcess
          object from a dictionary.

        Input
          entry: the dictinary object
        """
        self.logger.debug('FROM_DICT called')

        self.uuid = entry['uuid']
        self.pid = entry['pid']
        self.ppid = entry['ppid']
        self.process_name = entry['process_name']
        self.process_cmd_line = entry['process_cmd_line']
        self.process_imphash = entry['process_imphash']
        self.process_owner = entry['process_owner']
        self.parent_uuid = entry['parent_uuid']
        self.parent = None

        for dentry in entry['dlls']:
            try:
                bdll = BaselineDll()
                bdll.from_dict(dentry)
                self.dlls.append(bdll)
            except Exception as e:
                self.logger.warning('Dll skipped! (%d)(%s)(%s)' % (self.pid, type(e).__name__, str(e)))

    def to_json(self) -> str:
        """to_json

        This function is responsible for exporting a BaselineProcess object to
          JSON string

        Returns
          str
        """
        self.logger.debug('TO_JSON called')

        return json.dumps(self.to_dict(), indent=4)

    def __str__(self):
        """___str__

        This function is responsible for returning the string representation of
          a BaselineProcess object.

        Returns
          str
        """
        self.logger.debug('__STR__ called')

        return str(self.to_dict())

    def get_cmd_line(self,
                     process: object,
                     context: framework.interfaces.context.ContextInterface) -> str:
        """get_cmd_line

        This function is responsible for extracting the command line used to
          start the process from the process environment block (PEB)

        Returns
          str

        Input
          process: Volatility EPROCESS object
          context: Volatility context object
        """
        self.logger.debug('GET_CMD_LINE called')

        try:
            proc_layer_name = process.add_process_layer()
            kernel_table_name = context.config['PsList.nt_symbols']

            peb = context.object(kernel_table_name + framework.constants.BANG + "_PEB",
                                 layer_name = proc_layer_name,
                                 offset = process.Peb)
            return peb.ProcessParameters.CommandLine.get_string()
        except Exception as e:
            self.logger.warning('Process commandline could not be extracted! (%d)(%s)(%s)' % (self.pid, type(e).__name__, str(e)))
            return ''

    def get_dlls(self,
                 process: object,
                 context: framework.interfaces.context.ContextInterface) -> list:
        """get_dlls

        This function is responsible for extracting the DLLs loaded into the
        process.

        Returns
          list

        Input
          process: Volatility EPROCESS object
          content: Volatility context object
        """
        self.logger.debug('GET_DLLS called')

        tmp_dlls = []

        process_layer_name = ''
        try:
            process_layer_name = process.add_process_layer()
        except Exception as e:
            self.logger.warning('Process layer could not be added! (%d)(%s)(%s)' % (self.pid, type(e).__name__, str(e)))
            return []

        dll_list = None
        try:
            dll_list = process.load_order_modules()
        except Exception as e:
            self.logger.warning('DLLs could not be identified! (%d)(%s)(%s)' % (self.pid, type(e).__name__, str(e)))
            return []

        for dll in dll_list:
            try:
                tmp_dll = BaselineDll()
                tmp_dll.from_dll(dll_entry = dll,
                                 context = context,
                                 process_layer_name = process_layer_name)
                tmp_dlls.append(tmp_dll)
            except Exception as e:
                self.logger.warning('Dll skipped! (%d)(%s)(%s)(%s)' % (self.pid, hex(dll.DllBase), type(e).__name__, str(e)))
                continue

        return tmp_dlls

    def dump_pe(self,
                process: object,
                context: framework.interfaces.context.ContextInterface,
                process_layer_name: str) -> io.BytesIO:
        """dump_pe

        This function is responsible for reconstructing the PE image of the
          process from memory.

        Returns
          BytesIO stream

        Input
          process: Volatility EPROCESS object
          context: Volatility context object
          process_layer_name: str
        """
        self.logger.debug('DUMP_PE called')

        try:
            kernel_table_name = context.config['PsList.nt_symbols']
            pe_table_name = framework.symbols.intermed.IntermediateSymbolTable.create(context = context,
                                                                                      config_path = '',
                                                                                      sub_path = "windows",
                                                                                      filename = "pe",
                                                                                      class_types = framework.symbols.windows.extensions.pe.class_types)
            peb = context.object(kernel_table_name + framework.constants.BANG + "_PEB",
                                 layer_name = process_layer_name,
                                 offset = process.Peb)

            dos_header = context.object(pe_table_name + framework.constants.BANG + "_IMAGE_DOS_HEADER",
                                        offset = peb.ImageBaseAddress,
                                        layer_name = process_layer_name)
            pe_data = io.BytesIO(bytes())

            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)

            pe_data.seek(0)
            return pe_data
        except Exception as e:
            raise Exception('Process PE data could not be extracted! (%d)(%s)(%s)' % (self.pid, type(e).__name__, str(e)))

class BaselineDll(object):
    """BaselineDll class

    This class describes a DLL object with the properties used during the
    comparison process.
    """
    def __init__(self):
        """__init__

        Constructor
        """
        self.logger = logging.getLogger('BaselineDll')
        self.logger.debug('__INIT__ called')

        self.dll_name = ''
        self.dll_path = ''
        self.dll_base = -1
        self.dll_image_size = -1
        self.dll_imphash = ''

    @property
    def dll_name(self) -> str:
        """dll_name property getter

        Returns string containing the dll name stored in the internal
          __dll_name field containing the DLL name from the _LDR_DATA_TABLE_ENTRY
          structure in the PEB
        """
        self.logger.debug('DLL_NAME property getter called')

        return self.__dll_name

    @dll_name.setter
    def dll_name(self,
                 dll_name: str):
        """dll_name property setter

        Sets the internal __dll_name field.
        """
        self.logger.debug('DLL_NAME property setter called')

        self.__dll_name = dll_name

    @property
    def dll_path(self) -> str:
        """dll_path property getter

        Returns string containing the dll path stored in the internal
          __dll_path field containing the DLL path from the _LDR_DATA_TABLE_ENTRY
          structure in the PEB
        """
        self.logger.debug('DLL_PATH property getter called')

        return self.__dll_path

    @dll_path.setter
    def dll_path(self,
                 dll_path: str):
        """dll_path property setter

        Sets the internal __dll_path field.
        """
        self.logger.debug('DLL_PATH property setter called')

        self.__dll_path = dll_path

    @property
    def dll_imphash(self) -> str:
        """dll_imphash property getter

        Returns string containing the dll import hash stored in the internal
          __dll_imphash field.
        """
        self.logger.debug('DLL_IMPHASH property getter called')

        return self.__dll_imphash

    @dll_imphash.setter
    def dll_imphash(self,
                    imphash: str):
        """dll_imphash property setter

        Sets the internal __dll_imphash field.
        """
        self.logger.debug('DLL_IMPHASH property setter called')

        self.__dll_imphash = imphash

    @property
    def dll_base(self) -> int:
        """dll_base property getter

        Returns integer containing the dll base address stored in the internal
          __dll_base field containing the DLL base address from the
          _LDR_DATA_TABLE_ENTRY structure in the PEB
        """
        self.logger.debug('DLL_BASE property getter called')

        return self.__dll_base

    @dll_base.setter
    def dll_base(self,
                 dll_base: int):
        """dll_base property setter

        Sets the internal __dll_base field.
        """
        self.logger.debug('DLL_BASE property setter called')

        self.__dll_base = dll_base

    @property
    def dll_image_size(self) -> int:
        """dll_image_size property getter

        Returns integer containing the dll image size stored in the internal
          __dll_image_size field containing the DLL image size address from the
          _LDR_DATA_TABLE_ENTRY structure in the PEB
        """
        self.logger.debug('DLL_IMAGE_SIZE property getter called')

        return self.__dll_image_size

    @dll_image_size.setter
    def dll_image_size(self,
                 dll_image_size: int):
        """dll_image_size property setter

        Sets the internal __dll_image_size field.
        """
        self.logger.debug('DLL_IMAGE_SIZE property setter called')

        self.__dll_image_size = dll_image_size

    def is_same_as(self,
                   dll: object,
                   compare_imphash: bool) -> bool:
        """is_same_as

        This function is responsible for comparing two BaselineDll objects.
        Returns
          boolean

        Input
          process: BaselineProcess object
          compare_imphash: boolean /also compare import hashes/
        """
        self.logger.debug('IS_SAME_AS called')

        same_name = self.dll_name.lower() == dll.dll_name.lower()
        same_path = self.dll_path.lower() == dll.dll_path.lower()
        same_size = self.dll_image_size == dll.dll_image_size
        same_imphash = self.dll_imphash == dll.dll_imphash

        result = same_name and same_path and same_size

        if compare_imphash:
            result = result and same_imphash

        return result

    def from_dll(self,
                 dll_entry: object,
                 context: framework.interfaces.context.ContextInterface,
                 process_layer_name: str):
        """from_dll

        This function is responsible for loading the content of a BaselineDLL
          object from a dll object returned by the Volatility framework and
          filling in the internal fields with it.

        Input
          dll_entry: Volatility DLL object
          context: Volatility context object
          process_layer_name: str
        """
        self.logger.debug('FROM_DLL called')

        # Extract basic DLL info
        self.dll_base = dll_entry.DllBase
        self.logger.info('Base: %s' % (hex(self.dll_base)))
        self.dll_image_size = dll_entry.SizeOfImage

        # Extract DLL name
        try:
            self.dll_name = dll_entry.BaseDllName.get_string()
        except Exception as e:
            self.logger.warning('DLL name cannot be extracted! (%s)(%s)(%s)' % (hex(self.dll_base), type(e).__name__, str(e)))
            raise Exception('DLL name cannot be extracted! (%s)(%s)(%s)' % (hex(self.dll_base), type(e).__name__, str(e)))

        # Extract DLL path
        try:
            self.dll_path = dll_entry.FullDllName.get_string()
        except Exception as e:
            self.logger.warning('DLL path cannot be extracted! (%s)(%s)(%s)' % (hex(self.dll_base), type(e).__name__, str(e)))
            raise Exception('DLL path cannot be extracted! (%s)(%s)(%s)' % (hex(self.dll_base), type(e).__name__, str(e)))

        # Calculate imphash
        try:
            peobj = pefile.PE(data = self.dump_pe(dll_entry = dll_entry,
                                                  context = context,
                                                  process_layer_name = process_layer_name).read())
            try:
                self.dll_imphash = peobj.get_imphash()
            except Exception as f:
                self.logger.warning('DLL imphash could not be calculated! (%s)(%s)(%s)' % (hex(self.dll_base), type(f).__name__, str(f)))
                self.dll_imphash = ''
        except Exception as e:
            self.logger.warning('DLL PE object could not be created! (%s)(%s)(%s)' % (hex(self.dll_base), type(e).__name__, str(e)))
            self.dll_imphash = ''

    def to_dict(self) -> dict:
        """to_dict

        This function is responsible for exporting a BaselineDll object into
          a dictionary.

        Returns
          dict
        """
        self.logger.debug('TO_DICT called')

        return {
            'dll_name': self.dll_name,
            'dll_path': self.dll_path,
            'dll_imphash': self.dll_imphash,
            'dll_base': self.dll_base,
            'dll_image_size': self.dll_image_size
        }

    def from_dict(self,
                  entry: dict):
        """from_dict

        This function is responsible for loading the content of a BaselineDll
          object from a dictionary.

        Input
          entry: the dictinary object
        """
        self.logger.debug('FROM_DICT called')

        self.dll_name = entry['dll_name']
        self.dll_path = entry['dll_path']
        self.dll_imphash = entry['dll_imphash']
        self.dll_base = entry['dll_base']
        self.dll_image_size = entry['dll_image_size']

    def to_json(self) -> str:
        """to_json

        This function is responsible for exporting a BaselineDll object to JSON
          string

        Returns
          str
        """
        self.logger.debug('TO_JSON called')

        return json.dumps(self.to_dict(), indent=4)

    def __str__(self):
        """___str__

        This function is responsible for returning the string representation of
          a BaselineDll object.

        Returns
          str
        """
        self.logger.debug('__STR__ called')

        return str(self.to_dict())

    def dump_pe(self,
                dll_entry: object,
                context: framework.interfaces.context.ContextInterface,
                process_layer_name: str) -> io.BytesIO:
        """dump_pe

        This function is responsible for reconstructing the PE image of the DLL
          from memory.

        Returns
          BytesIO stream

        Input
          dll_entry: Volatility DLL object
          context: Volatility context object
          process_layer_name: str
        """
        self.logger.debug('DUMP_PE called')

        try:
            pe_table_name = framework.symbols.intermed.IntermediateSymbolTable.create(context = context,
                                                                                      config_path = '',
                                                                                      sub_path = "windows",
                                                                                      filename = "pe",
                                                                                      class_types = framework.symbols.windows.extensions.pe.class_types)

            dos_header = context.object(pe_table_name + framework.constants.BANG + "_IMAGE_DOS_HEADER",
                                        offset = dll_entry.DllBase,
                                        layer_name = process_layer_name)
            pe_data = io.BytesIO(bytes())

            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)

            pe_data.seek(0)
            return pe_data
        except Exception as e:
            self.logger.warning('DLL PE data could not be extracted! (%s)(%s)(%s)' % (hex(self.dll_base), type(e).__name__, str(e)))
            raise Exception('DLL PE data could not be extracted! (%s)(%s)(%s)' % (hex(self.dll_base), type(e).__name__, str(e)))

class BaselineProcessList(object):
    """BaselineProcessList class

    This class describes a list object containing BaselineProcess objects
    """
    def __init__(self):
        """__init__

        Constructor
        """
        self.logger = logging.getLogger('BaselineProcessList')
        self.logger.debug('__INIT__ called')

        self.processes = []

    @property
    def processes(self) -> list:
        """processes property getter

        Returns list with the BaselineProcess objects
        """
        self.logger.debug('PROCESSES property getter called')

        return self.__processes

    @processes.setter
    def processes(self,
                  processes: list):
        """processes property setter

        Sets the internal field __processes
        """
        self.logger.debug('PROCESSES property setter called')

        self.__processes = processes

    def collect_dll_statistics(self,
                               compare_imphash: bool) -> list:
        """collect_dll_statistics

        This function collects statistics regarding DLLs loaded into the process
          objects in its field __processes

        Returns
          list: containing entryies like the one below

          { 'dll': BaselineDll object,
            'frequency_of_occurence': int }
        """
        self.logger.debug('COLLECT_DLL_STATISTICS property getter called')

        dll_statistics = [] # list containing following DLL information
                            #  dll: BaselineDLL object
                            #  frequency_of_occurence: integer
        for p in self.processes:
            for dll in p.dlls:
                found = False
                for d in dll_statistics:
                    if d['dll'].is_same_as(dll,compare_imphash):
                        d['frequency_of_occurence'] += 1
                        found = True
                        break
                if not found:
                    dll_statistics.append({
                        'dll': dll,
                        'frequency_of_occurence': 1
                    })

        return dll_statistics

    def collect_process_statistics(self,
                                   compare_imphash: bool,
                                   compare_owner: bool,
                                   compare_cmdline: bool) -> list:
        """collect_process_statistics

        This function collects statistics regarding processes contained in its
          field __processes

        Returns
          list: containing entryies like the one below

          { 'process': BaselineProcess object,
            'frequency_of_occurence': int }
        """
        self.logger.debug('COLLECT_PROCESS_STATISTICS property getter called')

        process_statistics = [] # list containing following DLL information
                                #  process: BaselineProcess object
                                #  frequency_of_occurence: integer

        for proc in self.processes:
            found = False
            for p in process_statistics:
                if p['process'].is_same_as(proc,
                                           compare_imphash,
                                           compare_owner,
                                           compare_cmdline):
                    p['frequency_of_occurence'] += 1
                    found = True
                    break
            if not found:
                process_statistics.append({
                    'process': proc,
                    'frequency_of_occurence': 1
                })
        return process_statistics

    def from_image(self, image: str) -> list:
        """from_image

        This function is responsible for extracting processes from the memory
          image using the Volatility framework, creating BaselineProcess objects
          and storing them into its __processes list.

        Input
          image: str /path to the image/
        """
        self.logger.debug('FROM_IMAGE called')

        failures = framework.import_files(plugins, True)
        if len(failures) != 0:
            self.logger.warning('Volatility init failures! %s' % (str(failures)))

        config_path = ''
        ctx = framework.contexts.Context()
        ctx.config['automagic.LayerStacker.single_location'] = "file:" + request.pathname2url(image)
        available_automagics = framework.automagic.available(ctx)
        automagics = framework.automagic.choose_automagic(available_automagics,
                                                          plugins.windows.pslist.PsList)
        errors = framework.automagic.run(automagics,
                                         ctx,
                                         plugins.windows.pslist.PsList,
                                         config_path,
                                         progress_callback = PrintedProgress())
        self.logger.debug('Errors: %s' % (errors))
        unsatisfied = plugins.windows.pslist.PsList.unsatisfied(ctx, 'PsList')
        self.logger.debug('Unsatisfied: %s' % (unsatisfied))
        constructed = framework.plugins.construct_plugin(context = ctx,
                                                         automagics = automagics,
                                                         plugin = plugins.windows.pslist.PsList,
                                                         base_config_path = config_path,
                                                         progress_callback = PrintedProgress(),
                                                         open_method = None)
        processes = constructed.list_processes(context=ctx,
                                               layer_name = ctx.config['PsList.primary'],
                                               symbol_table = ctx.config['PsList.nt_symbols'])
        try:
            for p in processes:
                try:
                    # Instantiate process object
                    tmp_process = BaselineProcess()
                    tmp_process.from_process(process = p,
                                             context = ctx)
                    # Add process object to result list
                    self.processes.append(tmp_process)
                except Exception as e:
                    self.logger.warning('Process skipped! (%s)' % (str(e)))
                    continue
        except Exception as e:
            self.logger.warning('Error during getting processes! (%s)' % (str(e)))
            pass

        # Determine parents
        for bp in self.processes:
            for tmp_p in self.processes:
                if bp.ppid == tmp_p.pid:
                    bp.parent = tmp_p

    def to_json(self) -> str:
        """to_json

        This function is responsible for exporting a BaselineProcessList object
          to JSON string

        Returns
          str
        """
        self.logger.debug('TO_JSON called')

        return json.dumps([p.to_dict() for p in self.processes])

    def from_json(self,
                  jsonfile: str):
        """from_json

        This function is responsible for loading the content of a
          BaselineProcessList object from a JSON file.

        Input
          jsonfile: str /path the JSON file/
        """
        self.logger.debug('FROM_JSON called')

        baselinejson = open(jsonfile, 'r')
        list = None
        try:
            list = json.load(baselinejson)
            baselinejson.close()
        except Exception as e:
            self.logger.error('Could not parse JSON content! (%s)' % (str(e)))
            raise Exception('Could not parse JSON content! (%s)' % (str(e)))

        # Initial load of processes
        self.processes = []
        for entry in list:
            process = BaselineProcess()
            process.from_dict(entry)
            self.processes.append(process)

        # Fixing parent-child relationships based on GUIDs
        for p in self.processes:
            for tmp_p in self.processes:
                if p.parent_uuid == tmp_p.uuid:
                    p.parent = tmp_p
                    break

class BaselineDriver(object):
    """BaselineDriver class

    This class describes a driver object with the properties used during the
    comparison process.
    """
    def __init__(self):
        """__init__

        Constructor
        """
        self.logger = logging.getLogger('BaselineDriver')
        self.logger.debug('__INIT__ called')

        self.driver_name = ''
        self.driver_path = ''
        self.driver_image_size = -1
        self.driver_imphash = ''

    def from_driver(self,
                 driver_entry: object,
                 context: object,
                 driver_layer_name: str):
        """from_driver

        This function is responsible for loading the content of a BaselineDriver
          object from a driver object returned by the Volatility framework and
          filling in the internal fields with it.

        Input
          dll_entry: Volatility driver object
          context: Volatility context object
          driver_layer_name: str
        """
        self.logger.debug('FROM_DRIVER called')

        try:
            self.driver_name = driver_entry.BaseDllName.get_string()
        except Exception as e:
            self.logger.error('Driver name could not be determined!')
            raise Exception('Driver name could not be determined!')

        try:
            self.driver_path = driver_entry.FullDllName.get_string()
        except Exception as e:
            self.logger.error('Driver path could not be determined!')
            raise Exception('Driver path could not be determined!')

        try:
            self.driver_image_size = driver_entry.SizeOfImage
        except Exception as e:
            self.logger.error('Driver image size could not be determined!')
            raise Exception('Driver image size could not be determined!')

        pebuff = self.dump_pe(driver = driver_entry,
                              context = context)
        if pebuff != None:
            peobj = None
            try:
                peobj = pefile.PE(data=pebuff.read())
                try:
                    self.driver_imphash = peobj.get_imphash()
                except Exception as f:
                    self.logger.warning('Import Hash could not be calculated! (%s)' % (str(f)))
                    self.driver_imphash = ''
            except Exception as e:
                self.logger.warning('PE object could not be created! (%s)' % (str(e)))
                self.driver_imphash = ''
        else:
            self.logger.warning('PE dump could not be created!')
            self.driver_imphash = ''

    @property
    def driver_name(self) -> str:
        """driver_name proprty getter

        Returns string with driver name from internal __driver_name field
        containing the driver name (BaseDllName) from _KLDR_DATA_TABLE_ENTRY /
        _LDR_DATA_TABLE_ENTRY structure
        """
        self.logger.debug('DRIVER_NAME property getter called')

        return self.__driver_name

    @driver_name.setter
    def driver_name(self,
                    driver_name: str):
        """driver_name proprty setter

        Sets the internal __driver_name field.
        """
        self.logger.debug('DRIVER_NAME property setter called')

        self.__driver_name = driver_name

    @property
    def driver_path(self) -> str:
        """driver_path proprty getter

        Returns string with driver name from internal __driver_path field
        containing the driver name (FullDllName) from _KLDR_DATA_TABLE_ENTRY /
        _LDR_DATA_TABLE_ENTRY structure
        """
        self.logger.debug('DRIVER_PATH property getter called')

        return self.__driver_path

    @driver_path.setter
    def driver_path(self,
                    driver_path: str):
        """driver_path proprty setter

        Sets the internal __driver_path field.
        """
        self.logger.debug('DRIVER_PATH property setter called')

        self.__driver_path = driver_path

    @property
    def driver_image_size(self) -> int:
        """driver_image_size proprty getter

        Returns integer with driver name from internal __driver_image_size field
        containing the driver image size from _KLDR_DATA_TABLE_ENTRY /
        _LDR_DATA_TABLE_ENTRY structure
        """
        self.logger.debug('DRIVER_IMAGE_SIZE property getter called')

        return self.__driver_image_size

    @driver_image_size.setter
    def driver_image_size(self,
                    driver_image_size: int):
        """driver_image_size proprty setter

        Sets the internal __driver_image_size field.
        """
        self.logger.debug('DRIVER_IMAGE_SIZE property setter called')

        self.__driver_image_size = driver_image_size

    @property
    def driver_imphash(self) -> str:
        """driver_imphash proprty getter

        Returns integer with driver name from internal __driver_imphash field.
        """
        self.logger.debug('DRIVER_IMPHASH property getter called')

        return self.__driver_imphash

    @driver_imphash.setter
    def driver_imphash(self,
                    driver_imphash: str):
        """driver_imphash proprty setter

        Sets the internal __driver_imphash field.
        """
        self.logger.debug('DRIVER_IMPHASH property setter called')

        self.__driver_imphash = driver_imphash

    def to_dict(self) -> dict:
        """to_dict

        This function is responsible for exporting a BaselineDriver object into
          a dictionary.

        Returns
          dict
        """
        self.logger.debug('TO_DICT called')

        return {
            'driver_name': self.driver_name,
            'driver_path': self.driver_path,
            'driver_imphash': self.driver_imphash,
            'driver_image_size': self.driver_image_size
        }

    def from_dict(self,
                  entry: dict):
        """from_dict

        This function is responsible for loading the content of a BaselineDriver
          object from a dictionary.

        Input
          entry: the dictinary object
        """
        self.logger.debug('FROM_DICT called')

        self.driver_name = entry['driver_name']
        self.driver_path = entry['driver_path']
        self.driver_imphash = entry['driver_imphash']
        self.driver_image_size = entry['driver_image_size']

    def to_json(self):
        self.logger.debug('TO_JSON called')

        return json.dumps(self.to_dict(), indent=4)

    def is_same_as(self,
                   driver: object,
                   compare_imphash: bool) -> bool:
        """is_same_as

        This function is responsible for comparing two BaselineDriver objects.
        Returns
          boolean

        Input
          process: BaselineProcess object
          compare_imphash: boolean /also compare import hashes/
        """
        self.logger.debug('IS_SAME_AS called')

        same_name = self.driver_name.lower() == driver.driver_name.lower()
        same_path = self.driver_path.lower() == driver.driver_path.lower()
        same_size = self.driver_image_size == driver.driver_image_size
        same_imphash = self.driver_imphash == driver.driver_imphash

        result = same_name and same_path and same_size

        if compare_imphash:
            result = result and same_imphash

        return result

    def dump_pe(self,
                driver: object,
                context: framework.interfaces.context.ContextInterface) -> io.BytesIO:
        """dump_pe

        This function is responsible for reconstructing the PE image of the driver
          from memory.

        Returns
          BytesIO stream

        Input
          dll_entry: Volatility driver object
          context: Volatility context object
        """
        self.logger.debug('DUMP_PE called')

        try:
            layer_name = driver.vol.layer_name

            pe_table_name = framework.symbols.intermed.IntermediateSymbolTable.create(context = context,
                                                                                      config_path = '',
                                                                                      sub_path = "windows",
                                                                                      filename = "pe",
                                                                                      class_types = framework.symbols.windows.extensions.pe.class_types)

            dos_header = context.object(pe_table_name + framework.constants.BANG + "_IMAGE_DOS_HEADER",
                                        offset = driver.DllBase,
                                        layer_name = layer_name)
            pe_data = io.BytesIO(bytes())

            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)

            pe_data.seek(0)
            return pe_data
        except Exception as e:
            self.logger.warning('Error dumping PE data! (%s)' % (str(e)))
            return None

class BaselineDriverList(object):
    """BaselineDriverList class

    This class describes a list object containing BaselineDriver objects.
    """
    def __init__(self):
        """__init__

        Constructor
        """
        self.logger = logging.getLogger('BaselineDriverList')
        self.logger.debug('__INIT__ called')

        self.drivers = []

    @property
    def drivers(self) -> list:
        """drivers property getter

        Returns list containing the BaselineDriver objects stored in the internal
          __drivers field.
        """
        self.logger.debug('DRIVERS property getter called')

        return self.__drivers

    @drivers.setter
    def drivers(self,
                drivers: list):
        """drivers property setter

        Sets the internal __drivers field.
        """
        self.logger.debug('DRIVERS property setter called')


        self.__drivers = drivers

    def from_image(self,
                   image: str):
        """from_image

        This function is responsible for extracting drivers from the memory
          image using the Volatility framework, creating BaselineDriver objects
          and storing them into its __drivers list.

        Input
          image: str /path to the image/
        """
        self.logger.debug('FROM_IMAGE called')

        failures = framework.import_files(plugins, True)
        if len(failures) != 0:
            self.logger.warning('Volatility init failures! %s' % (str(failures)))

        config_path = ''
        ctx = framework.contexts.Context()
        ctx.config['automagic.LayerStacker.single_location'] = "file:" + request.pathname2url(image)
        available_automagics = framework.automagic.available(ctx)
        automagics = framework.automagic.choose_automagic(available_automagics,
                                                          plugins.windows.pslist.PsList)
        errors = framework.automagic.run(automagics,
                                         ctx,
                                         plugins.windows.pslist.PsList,
                                         config_path,
                                         progress_callback = PrintedProgress())
        self.logger.debug('Errors: %s' % (errors))
        unsatisfied = plugins.windows.pslist.PsList.unsatisfied(ctx, 'PsList')
        self.logger.debug('Unsatisfied: %s' % (unsatisfied))
        constructed = framework.plugins.construct_plugin(context = ctx,
                                                         automagics = automagics,
                                                         plugin = plugins.windows.modules.Modules,
                                                         base_config_path = config_path,
                                                         progress_callback = PrintedProgress(),
                                                         open_method = None)
        modules = constructed.list_modules(context = ctx,
                                           layer_name = ctx.config['Modules.primary'],
                                           symbol_table = ctx.config['Modules.nt_symbols'])
        for module in modules:
            #print(str(module.vol.offset) + "\t" + module.BaseDllName.get_string() + "\t" + module.FullDllName.get_string() + "\t" + str(module.SizeOfImage))
            try:
                driver = BaselineDriver()
                driver.from_driver(driver_entry = module,
                                   context = ctx,
                                   driver_layer_name = '')
                self.drivers.append(driver)
            except Exception as e:
                self.logger.warning('Driver skipped! (%s)' % (str(e)))

    def to_json(self) -> dict:
        """to_json

        This function is responsible for exporting a BaselineDriverList object
          to JSON string

        Returns
          str
        """
        self.logger.debug('TO_JSON called')

        return json.dumps([d.to_dict() for d in self.drivers])

    def from_json(self,
                  jsonfile: str):
        """from_json

        This function is responsible for loading the content of a
          BaselineDriverList object from a JSON file.

        Input
          jsonfile: str /path the JSON file/
        """
        self.logger.debug('FROM_JSON called')

        baselinejson = open(jsonfile, 'r')
        list = None
        try:
            list = json.load(baselinejson)
            baselinejson.close()
        except Exception as e:
            self.logger.error('Could not parse JSON content! (%s)' % (str(e)))
            raise Exception('Could not parse JSON content! (%s)' % (str(e)))

        # Initial load of drivers
        self.drivers = []
        for entry in list:
            driver = BaselineDriver()
            driver.from_dict(entry)
            self.drivers.append(driver)

    def collect_driver_statistics(self,
                                   compare_imphash: bool) -> list:
        """collect_driver_statistics

        This function collects statistics regarding drivers contained in its
          field __drivers

        Returns
          list: containing entryies like the one below

          { 'driver': BaselineDriver object,
            'frequency_of_occurence': int }
        """
        self.logger.debug('COLLECT_DRIVER_STATISTICS property getter called')

        driver_statistics = [] # list containing following service information
                               #  driver: BaselineDriver object
                               #  frequency_of_occurence: integer

        for drv in self.drivers:
            found = False
            for d in driver_statistics:
                if d['driver'].is_same_as(drv,
                                          compare_imphash):
                    d['frequency_of_occurence'] += 1
                    found = True
                    break
            if not found:
                driver_statistics.append({
                    'driver': drv,
                    'frequency_of_occurence': 1
                })
        return driver_statistics

class BaselineService(object):
    """BaselineService class

    This class describes a service object with the properties used during the
    comparison process.
    """
    def __init__(self):
        """__init__

        Constructor
        """
        self.logger = logging.getLogger('BaselineService')
        self.logger.debug('__INIT__ called')

        self.service_name = ''
        self.service_displayname = ''

        self.service_type = ''
        self.service_start = ''
        self.service_state = ''

        self.service_process_binary = ''
        self.service_process_owner = ''

    @property
    def service_name(self) -> str:
        """service_name property getter

        Returns string with service name from the internal __service_name field
        containing the service name from the _SERVICE_RECORD structure.
        """
        self.logger.debug('SERVICE_NAME property getter called')

        return self.__service_name

    @service_name.setter
    def service_name(self,
                     service_name: str):
        """service_name property setter

        Sets the internal field __service_name
        """
        self.logger.debug('SERVICE_NAME property setter called')

        self.__service_name = service_name

    @property
    def service_displayname(self) -> str:
        """service_displayname property getter

        Returns string with service display name from the internal
          __service_displayname field containing the service displayname from
          the _SERVICE_RECORD structure.
        """
        self.logger.debug('SERVICE_DISPLAYNAME property getter called')

        return self.__service_displayname

    @service_displayname.setter
    def service_displayname(self,
                            service_displayname: str):
        """service_displayname property setter

        Sets the internal field __service_displayname
        """
        self.logger.debug('SERVICE_DISPLAYNAME property setter called')

        self.__service_displayname = service_displayname

    @property
    def service_type(self) -> str:
        """service_type property getter

        Returns string with service type from the internal __service_type field
          containing the service type from the _SERVICE_RECORD structure.
        """
        self.logger.debug('SERVICE_TYPE property getter called')

        return self.__service_type

    @service_type.setter
    def service_type(self,
                     service_type: str):
        """service_type property setter

        Sets the internal field __service_type
        """
        self.logger.debug('SERVICE_TYPE property setter called')

        self.__service_type = service_type

    @property
    def service_start(self) -> str:
        """service_start property getter

        Returns string with service start from the internal __service_start
          field containing the service start from the _SERVICE_RECORD
          structure.
        """
        self.logger.debug('SERVICE_START property getter called')

        return self.__service_start

    @service_start.setter
    def service_start(self,
                      service_start: str):
        """service_start property setter

        Sets the internal field __service_start
        """
        self.logger.debug('SERVICE_START property setter called')

        self.__service_start = service_start

    @property
    def service_state(self) -> str:
        """service_state property getter

        Returns string with service state from the internal __service_state
          field containing the service state from the _SERVICE_RECORD structure.
        """
        self.logger.debug('SERVICE_STATE property getter called')

        return self.__service_state

    @service_state.setter
    def service_state(self,
                      service_state: str):
        """service_state property setter

        Sets the internal field __service_state
        """
        self.logger.debug('SERVICE_STATE property setter called')

        self.__service_state = service_state

    @property
    def service_process_binary(self) -> str:
        """service_process_binary property getter

        Returns string with service process binary from the internal
          __service_process_binary field containing the service binary from the
          _SERVICE_RECORD structure.
        """
        self.logger.debug('SERVICE_PROCESS_BINARY property getter called')

        return self.__service_process_binary

    @service_process_binary.setter
    def service_process_binary(self,
                               service_process_binary):
        """service_process_binary property setter

        Sets the internal field __service_process_binary
        """
        self.logger.debug('SERVICE_PROCESS_BINARY property setter called')

        self.__service_process_binary = service_process_binary

    @property
    def service_process_owner(self) -> str:
        """service_process_owner property getter

        Returns string with service process owner from the internal
          __service_process_owner field containing the service process owner
          from the EPROCESS object associated with the service if the service is
          running.
        """
        self.logger.debug('SERVICE_PROCESS_OWNER property getter called')

        return self.__service_process_owner

    @service_process_owner.setter
    def service_process_owner(self,
                              service_process_owner: str):
        """service_process_owner property setter

        Sets the internal field __service_process_owner
        """
        self.logger.debug('SERVICE_PROCESS_OWNER property setter called')
        self.__service_process_owner = service_process_owner

    def to_dict(self) -> dict:
        """to_dict

        This function is responsible for exporting a BaselineService object into
          a dictionary.

        Returns
          dict
        """
        self.logger.debug('TO_DICT called')

        return {
            'service_name': self.service_name,
            'service_displayname': self.service_displayname,
            'service_type': self.service_type,
            'service_start': self.service_start,
            'service_state': self.service_state,
            'service_process_binary': self.service_process_binary,
            'service_process_owner': self.service_process_owner
        }

    def from_dict(self,
                  service_dict: dict):
        """from_dict

        This function is responsible for loading the content of a BaselineService
          object from a dictionary.

        Input
          entry: the dictinary object
        """
        self.logger.debug('FROM_DICT called')

        self.service_name = service_dict['service_name']
        self.service_displayname = service_dict['service_displayname']

        self.service_type = service_dict['service_type']
        self.service_start = service_dict['service_start']
        self.service_state = service_dict['service_state']

        self.service_process_binary = service_dict['service_process_binary']
        self.service_process_owner = service_dict['service_process_owner']

    def from_service(self,
                     service_entry: object,
                     process_list: BaselineProcessList):
        """from_service

        This function is responsible for loading the content of a BaselineService
          object from a service record returned by the Volatility framework and
          filling in the internal fields with it.

        Input
          dll_entry: Volatility DLL object
          context: Volatility context object
          process_layer_name: str
        """
        self.logger.debug('FROM_SERVICE called')

        if not isinstance(service_entry[0], str):
            self.logger.error('Service name could not be determined!')
            raise Exception('Service name could not be determined!')

        self.service_name = service_entry[0]
        self.service_displayname = service_entry[1] if isinstance(service_entry[1], str) else ''

        self.service_type = service_entry[2]
        self.service_start = service_entry[3]
        self.service_state = service_entry[4]

        self.service_process_binary = service_entry[5] if isinstance(service_entry[5], str) else ''
        pid = service_entry[6] if isinstance(service_entry[6], int) else -1
        proc = None
        if pid > -1:
            for p in process_list.processes:
                if p.pid == pid:
                    proc = p
                    break
        if proc == None:
            self.service_process_owner = ''
        else:
            self.service_process_owner = proc.process_owner

    def is_same_as(self,
                   service: object,
                   compare_owner: bool,
                   compare_state: bool) -> bool:
        """is_same_as

        This function is responsible for comparing two BaselineService objects.
        Returns
          boolean

        Input
          process: BaselineService object
          compare_owner: boolean /also compare service process owners/
          compare_state: boolean /also compare service states/
        """
        self.logger.debug('IS_SAME_AS called')

        same_name = self.service_name.lower() == service.service_name.lower()
        same_displayname = self.service_displayname.lower() == service.service_displayname.lower()

        same_type = self.service_type.lower() == service.service_type.lower()
        same_start = self.service_start.lower() == service.service_start.lower()
        same_state = self.service_state.lower() == service.service_state.lower()
        same_owner = self.service_process_owner.lower() == service.service_process_owner.lower()
        same_binary = self.service_process_binary.lower() == service.service_process_binary.lower()

        result = same_name and same_displayname and same_type and same_start and same_binary

        if compare_owner:
            result = result and same_owner

        if compare_state:
            result = result and same_state

        return result

class BaselineServiceList(object):
    """BaselineServiceList class

    This class describes a list object containing BaselineService objects
    """
    def __init__(self):
        """__init__

        Constructor
        """
        self.logger = logging.getLogger('BaselineService')
        self.logger.debug('__INIT__ called')

        self.services = []

    @property
    def services(self) -> list:
        """services property getter

        Returns list containing BaselineService objects stored in the internal
          services field.
        """
        self.logger.debug('SERVICES property getter called')

        return self.__services

    @services.setter
    def services(self,
                 services: list):
        """services property setter

        Sets the internal __services field.
        """
        self.logger.debug('SERVICES property setter called')

        self.__services = services

    @staticmethod
    def create_service_table(context: framework.interfaces.context.ContextInterface, symbol_table: str, config_path: str) -> str:
        """Constructs a symbol table containing the symbols for services
        depending upon the operating system in use.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of the table containing the kernel symbols
            config_path: The configuration path for any settings required by the new table

        Returns:
            A symbol table containing the symbols necessary for services
        """

        native_types = context.symbol_space[symbol_table].natives
        is_64bit = framework.symbols.symbol_table_is_64bit(context, symbol_table)

        if framework.symbols.windows.versions.is_windows_xp(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-xp-x86"
        elif framework.symbols.windows.versions.is_xp_or_2003(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-xp-2003-x64"
        elif framework.symbols.windows.versions.is_win10_16299_or_later(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-win10-16299-x64"
        elif framework.symbols.windows.versions.is_win10_16299_or_later(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-win10-16299-x86"
        elif framework.symbols.windows.versions.is_win10_up_to_15063(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-win8-x64"
        elif framework.symbols.windows.versions.is_win10_up_to_15063(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-win8-x86"
        elif framework.symbols.windows.versions.is_win10_15063(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-win10-15063-x64"
        elif framework.symbols.windows.versions.is_win10_15063(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-win10-15063-x86"
        elif framework.symbols.windows.versions.is_windows_8_or_later(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-win8-x64"
        elif framework.symbols.windows.versions.is_windows_8_or_later(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-win8-x86"
        elif framework.symbols.windows.versions.is_vista_or_later(context = context, symbol_table = symbol_table) and is_64bit:
            symbol_filename = "services-vista-x64"
        elif framework.symbols.windows.versions.is_vista_or_later(context = context, symbol_table = symbol_table) and not is_64bit:
            symbol_filename = "services-vista-x86"
        else:
            raise NotImplementedError("This version of Windows is not supported!")

        return framework.symbols.intermed.IntermediateSymbolTable.create(context,
                                                                         config_path,
                                                                         "windows",
                                                                         symbol_filename,
                                                                         class_types = framework.symbols.windows.extensions.services.class_types,
                                                                         native_types = native_types)

    @staticmethod
    def get_record_tuple(service_record: framework.interfaces.objects.ObjectInterface):
        """get_record_tuple

        Returns a service record in a tuple
        """
        return (framework.renderers.format_hints.Hex(service_record.vol.offset), service_record.Order, service_record.get_pid(),
                service_record.Start.description, service_record.State.description, service_record.get_type(),
                service_record.get_name(), service_record.get_display(), service_record.get_binary())

    def to_json(self) -> str:
        """to_json

        This function is responsible for exporting a BaselineServiceList object
          to JSON string

        Returns
          str
        """
        self.logger.debug('TO_JSON called')

        return json.dumps([svc.to_dict() for svc in self.services])

    def from_json(self,
                  jsonfile: str):
        """from_json

        This function is responsible for loading the content of a
          BaselineProcessList object from a JSON file.

        Input
          jsonfile: str /path the JSON file/
        """
        self.logger.debug('FROM_JSON called')

        try:
            _json = open(jsonfile, 'r')
            json_content = json.load(_json)
            _json.close()
        except Exception as e:
            self.logger.error('Could not load JSON content! (%s)' % (str(e)))
            raise Exception('Could not load JSON content! (%s)' % (str(e)))

        for svc in json_content:
            try:
                service = BaselineService()
                service.from_dict(svc)
                self.services.append(service)
            except Exception as e:
                self.logger.error('Could not create service object from JSON! (%s)' % (str(e)))
                raise Exception('Could not create service object from JSON! (%s)' % (str(e)))

    def from_image(self,
                   image: str):
        """from_image

        This function is responsible for extracting services from the memory
          image using the Volatility framework, creating BaselineProcess objects
          and storing them into its __services list.

        Input
          image: str /path to the image/
        """
        self.logger.debug('FROM_IMAGE called')

        # Get processes
        processes = BaselineProcessList()
        processes.from_image(image)

        failures = framework.import_files(plugins, True)
        if len(failures) != 0:
            self.logger.warning('Volatility init failures! %s' % (str(failures)))

        config_path = ''
        ctx = framework.contexts.Context()
        ctx.config['automagic.LayerStacker.single_location'] = "file:" + request.pathname2url(image)
        available_automagics = framework.automagic.available(ctx)

        automagics = framework.automagic.choose_automagic(available_automagics,
                                                          plugins.windows.svcscan.SvcScan)
        errors = framework.automagic.run(automagics,
                                         ctx,
                                         plugins.windows.svcscan.SvcScan,
                                         config_path,
                                         progress_callback = PrintedProgress())
        self.logger.debug('Errors: %s' % (errors))
        unsatisfied = plugins.windows.svcscan.SvcScan.unsatisfied(ctx, 'SvcScan')
        self.logger.debug('Unsatisfied: %s' % (unsatisfied))

        service_table_name = self.create_service_table(context = ctx,
                                                       symbol_table = ctx.config["SvcScan.nt_symbols"],
                                                       config_path = config_path)
        relative_tag_offset = ctx.symbol_space.get_type(service_table_name + framework.constants.BANG +
                                                        "_SERVICE_RECORD").relative_child_offset("Tag")
        filter_func = plugins.windows.pslist.PsList.create_name_filter(["services.exe"])
        is_vista_or_later = framework.symbols.windows.versions.is_vista_or_later(context = ctx,
                                                                                 symbol_table = ctx.config["SvcScan.nt_symbols"])
        if is_vista_or_later:
            service_tag = b"serH"
        else:
            service_tag = b"sErv"

        try:
            seen = []
            for task in plugins.windows.pslist.PsList.list_processes(context = ctx,
                                                                     layer_name = ctx.config['SvcScan.primary'],
                                                                     symbol_table = ctx.config['SvcScan.nt_symbols'],
                                                                     filter_func = filter_func):
                proc_id = "Unknown"
                try:
                    proc_id = task.UniqueProcessId
                    proc_layer_name = task.add_process_layer()
                except exceptions.InvalidAddressException as excp:
                    vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                     excp.layer_name))
                    continue

                layer = ctx.layers[proc_layer_name]

                for offset in layer.scan(context = ctx,
                                         scanner = framework.layers.scanners.BytesScanner(needle = service_tag),
                                         sections = plugins.windows.vadyarascan.VadYaraScan.get_vad_maps(task)):

                    if not is_vista_or_later:
                        service_record = ctx.object(service_table_name + framework.constants.BANG + "_SERVICE_RECORD",
                                                    offset = offset - relative_tag_offset,
                                                    layer_name = proc_layer_name)

                        if not service_record.is_valid():
                            continue

                        svc_tuple = self.get_record_tuple(service_record)
                        svc = (svc_tuple[6], # name
                               svc_tuple[7], # display name
                               svc_tuple[5], # type
                               svc_tuple[3], # start
                               svc_tuple[4], # state
                               svc_tuple[8], # binary
                               svc_tuple[2]) # pid

                        if not svc in seen:
                            #print(svc)
                            seen.append(svc)
                            service = BaselineService()
                            service.from_service(service_entry = svc,
                                                 process_list = processes)

                            self.services.append(service)
                    else:
                        service_header = ctx.object(service_table_name + framework.constants.BANG + "_SERVICE_HEADER",
                                                    offset = offset,
                                                    layer_name = proc_layer_name)

                        if not service_header.is_valid():
                            continue

                        # since we walk the s-list backwards, if we've seen
                        # an object, then we've also seen all objects that
                        # exist before it, thus we can break at that time.
                        for service_record in service_header.ServiceRecord.traverse():
                            svc_tuple = self.get_record_tuple(service_record)
                            svc = (svc_tuple[6], # name
                                   svc_tuple[7], # display name
                                   svc_tuple[5], # type
                                   svc_tuple[3], # start
                                   svc_tuple[4], # state
                                   svc_tuple[8], # binary
                                   svc_tuple[2]) # pid

                            if not svc in seen:
                                #print(svc)
                                seen.append(svc)
                                service = BaselineService()
                                service.from_service(service_entry = svc,
                                                     process_list = processes)

                                self.services.append(service)
                            else:
                                break
        except Exception as e:
            self.logger.error('Error looping through processes! (%s)' % (str(e)))
            pass

    def collect_service_statistics(self,
                                   compare_owner: bool,
                                   compare_state: bool) -> list:
        """collect_service_statistics

        This function collects statistics regarding services contained in its
          field __service

        Returns
          list: containing entryies like the one below

          { 'service': BaselineService object,
            'frequency_of_occurence': int }
        """
        self.logger.debug('COLLECT_SERVICE_STATISTICS property getter called')

        service_statistics = [] # list containing following service information
                                #  service: BaselineService object
                                #  frequency_of_occurence: integer

        for svc in self.services:
            found = False
            for s in service_statistics:
                if s['service'].is_same_as(svc,
                                           compare_owner,
                                           compare_state):
                    s['frequency_of_occurence'] += 1
                    found = True
                    break
            if not found:
                service_statistics.append({
                    'service': svc,
                    'frequency_of_occurence': 1
                })
        return service_statistics
