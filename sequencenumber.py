import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32
import volatility.debug as debug
from volatility.renderers import TreeGrid

class sequencenumber(common.AbstractWindowsCommand):
    """ Print the order in which processes were created (Win10+) """

    def calculate(self):

        addr_space = utils.load_as(self._config)

        #plugin supports Windows 10+
        os_vsn_maj = addr_space.profile.metadata.get('major', 0)
        os_vsn_min = addr_space.profile.metadata.get('minor', 0)

        # plugin currently supports Windows 10 (6.4) and greater
        if (os_vsn_maj, os_vsn_min) not in [(6,4)]:
            debug.error("Plugin does not support Windows {0}.{1}. SequenceNumber is only present in Windows 10+".format(os_vsn_maj, os_vsn_min))
            return

        tasks = win32.tasks.pslist(addr_space)

        return tasks

    def render_text(self, outfd, data):

        self.table_header(outfd,
                        [("SequenceNumber","14"),
                        ("PID", "6"),
                        ("ProcessName", "15"),
                        ("CreateTime", "")]
                        )


        for task in data:
            self.table_row(outfd,
                            task.SequenceNumber,
                            task.UniqueProcessId,
                            task.ImageFileName,
                            str(task.CreateTime or ''))

    def unified_output(self, data):
        return TreeGrid([("SequenceNumber", int),
                        ("PID", int),
                        ("ProcessName", str),
                        ("CreateTime", str)],
                        self.generator(data))

    def generator(self, data):
        for task in data:
            yield (0, [int(task.SequenceNumber),
                        int(task.UniqueProcessId),
                        str(task.ImageFileName),
                        str(task.CreateTime or '')])
