import io
import datetime
import os
from os import path
from functools import wraps
import sys
sys.path.append(path.abspath('../volatility3'))
from volatility.framework import interfaces, configuration
from volatility.framework.renderers import format_hints
from typing import Dict, Type, Union, Any, List, Tuple

def file_handler_class_factory(dump_path, direct = True):
    output_dir = dump_path

    class FileHandler(interfaces.plugins.FileHandlerInterface):

        def _get_final_filename(self):
            """Gets the final filename"""
            if output_dir is None:
                raise TypeError("Output directory is not a string")
            os.makedirs(output_dir, exist_ok = True)

            pref_name_array = self.preferred_filename.split('.')
            filename, extension = os.path.join(output_dir, '.'.join(pref_name_array[:-1])), pref_name_array[-1]
            output_filename = "{}.{}".format(filename, extension)

            counter = 1
            while os.path.exists(output_filename):
                output_filename = "{}-{}.{}".format(filename, counter, extension)
                counter += 1
            return output_filename

    class MemFileHandler(io.BytesIO, FileHandler):
        def __init__(self, filename: str):
            io.BytesIO.__init__(self)
            FileHandler.__init__(self, filename)

        def close(self):
            # Don't overcommit
            if self.closed:
                return

            self.seek(0)

            output_filename = self._get_final_filename()

            with open(output_filename, "wb") as current_file:
                current_file.write(self.read())
                self._committed = True
                vollog.log(logging.INFO, "Saved stored plugin file: {}".format(output_filename))

            super().close()

    class DirectFileHandler(FileHandler):
        def __init__(self, filename: str):
            fd, self._name = tempfile.mkstemp(suffix = '.vol3', prefix = 'tmp_', dir = output_dir)
            self._file = io.open(fd, mode = 'w+b')
            FileHandler.__init__(self, filename)
            for item in dir(self._file):
                if not item.startswith('_') and not item in ['closed', 'close', 'mode', 'name']:
                    setattr(self, item, getattr(self._file, item))

        def __getattr__(self, item):
            return getattr(self._file, item)

        @property
        def closed(self):
            return self._file.closed

        @property
        def mode(self):
            return self._file.mode

        @property
        def name(self):
            return self._file.name

        def close(self):
            """Closes and commits the file (by moving the temporary file to the correct name"""
            # Don't overcommit
            if self._file.closed:
                return

            self._file.close()
            output_filename = self._get_final_filename()
            os.rename(self._name, output_filename)

    if direct:
        return DirectFileHandler
    else:
        return MemFileHandler

class PrintedProgress(object):
    """A progress handler that prints the progress value and the description
    onto the command line."""

    def __init__(self):
        self._max_message_len = 0

    def __call__(self, progress: Union[int, float], description: str = None):
        """A simple function for providing text-based feedback.

        .. warning:: Only for development use.

        Args:
            progress: Percentage of progress of the current procedure
        """
        message = "\rProgress: {0: 7.2f}\t\t{1:}".format(round(progress, 2), description or '')
        message_len = len(message)
        self._max_message_len = max([self._max_message_len, message_len])
        sys.stderr.write(message + (' ' * (self._max_message_len - message_len)) + '\r')


class MuteProgress(PrintedProgress):
    """A dummy progress handler that produces no output when called."""

    def __call__(self, progress: Union[int, float], description: str = None):
        pass

def quoted_optional(func):

    @wraps(func)
    def wrapped(x: Any) -> str:
        result = optional(func)(x)
        if result == "-" or result == "N/A":
            return ""
        if isinstance(x, format_hints.MultiTypeData) and x.converted_int:
            return "{}".format(result)
        if isinstance(x, int) and not isinstance(x, (format_hints.Hex, format_hints.Bin)):
            return "{}".format(result)
        return "\"{}\"".format(result)

    return wrapped

def hex_bytes_as_text(value: bytes) -> str:
    """
    Renders HexBytes as text.

    Args:
        value: A series of bytes to convert to text

    Returns:
        A text representation of the hexadecimal bytes plus their ascii equivalents, separated by newline characters
    """
    if not isinstance(value, bytes):
        raise TypeError("hex_bytes_as_text takes bytes not: {}".format(type(value)))
    ascii = []
    hex = []
    count = 0
    output = ""
    for byte in value:
        hex.append("{:02x}".format(byte))
        ascii.append(chr(byte) if 0x20 < byte <= 0x7E else ".")
        if (count % 8) == 7:
            output += "\n"
            output += " ".join(hex[count - 7:count + 1])
            output += "\t"
            output += "".join(ascii[count - 7:count + 1])
        count += 1
    return output

def display_disassembly(disasm: interfaces.renderers.Disassembly) -> str:
    """Renders a disassembly renderer type into string format.

    Args:
        disasm: Input disassembly objects

    Returns:
        A string as rendererd by capstone where available, otherwise output as if it were just bytes
    """

    if CAPSTONE_PRESENT:
        disasm_types = {
            'intel': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            'intel64': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            'arm': capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            'arm64': capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        }
        output = ""
        if disasm.architecture is not None:
            for i in disasm_types[disasm.architecture].disasm(disasm.data, disasm.offset):
                output += "\n0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
        return output
    return QuickTextRenderer._type_renderers[bytes](disasm.data)

_type_renderers = {
    format_hints.HexBytes: quoted_optional(hex_bytes_as_text),
    interfaces.renderers.Disassembly: quoted_optional(display_disassembly),
    datetime.datetime: lambda x: x.isoformat() if not isinstance(x, interfaces.renderers.BaseAbsentValue) else None,
    'default': lambda x: x
}

def process_unsatisfied_exceptions(excp):
        """Provide useful feedback if an exception occurs during requirement fulfillment."""
        # Add a blank newline
        print("")
        translation_failed = False
        symbols_failed = False
        for config_path in excp.unsatisfied:
            translation_failed = translation_failed or isinstance(
                excp.unsatisfied[config_path], configuration.requirements.TranslationLayerRequirement)
            symbols_failed = symbols_failed or isinstance(excp.unsatisfied[config_path],
                                                          configuration.requirements.SymbolTableRequirement)

            print("Unsatisfied requirement {}: {}".format(config_path, excp.unsatisfied[config_path].description))

        if symbols_failed:
            print("\nA symbol table requirement was not fulfilled.  Please verify that:\n"
                  "\tYou have the correct symbol file for the requirement\n"
                  "\tThe symbol file is under the correct directory or zip file\n"
                  "\tThe symbol file is named appropriately or contains the correct banner\n")
        if translation_failed:
            print("\nA translation layer requirement was not fulfilled.  Please verify that:\n"
                  "\tA file was provided to create this layer (by -f, --single-location or by config)\n"
                  "\tThe file exists and is readable\n"
                  "\tThe necessary symbols are present and identified by volatility")
