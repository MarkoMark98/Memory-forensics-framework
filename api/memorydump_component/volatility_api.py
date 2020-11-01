import json
from os import path
import sys
sys.path.append(path.abspath('../../../volatility3'))
sys.path.append(path.abspath('../../'))
from volatility import framework
from volatility.plugins.windows import pslist
from volatility.framework import contexts, automagic, exceptions, plugins, interfaces
from volatility.framework.interfaces.plugins import FileHandlerInterface
from utils.parser import _type_renderers, PrintedProgress, file_handler_class_factory, process_unsatisfied_exceptions
from typing import Dict, Type, Union, Any, List, Tuple

dump_path = path.realpath('/media/sf_SharedFolder/dumps/2gb//memdump.mem')

framework.require_interface_version(2, 0, 0)
ctx = contexts.Context()
config_path = interfaces.configuration.path_join('automagic', 'LayerStacker', 'single_location')
ctx.config['automagic.LayerStacker.single_location'] = 'file://'+dump_path

unsatisfied = interfaces.plugins.PluginInterface.unsatisfied(ctx, config_path)

automagics = automagic.available(ctx)
automagics = automagic.choose_automagic(automagics, pslist.PsList)
constructed = None
try:
    progress_callback = PrintedProgress()
    constructed = plugins.construct_plugin(ctx, automagics, pslist.PsList, config_path, progress_callback, file_handler_class_factory(dump_path))
except exceptions.UnsatisfiedException as excp:
            process_unsatisfied_exceptions(excp)
if constructed is not None:
    grid = constructed.run()
    outfd = open('result.json', 'w')
    outfd.write("\n")

    final_output = (
                {}, [])

    def visitor(
        node: interfaces.renderers.TreeNode, accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]
    ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
        # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
        acc_map, final_tree = accumulator
        node_dict = {'__children': []}  # type: Dict[str, Any]
        for column_index in range(len(grid.columns)):
            column = grid.columns[column_index]
            renderer = _type_renderers.get(column.type, _type_renderers['default'])
            data = renderer(list(node.values)[column_index])
            if isinstance(data, interfaces.renderers.BaseAbsentValue):
                data = None
            node_dict[column.name] = data
        if node.parent:
            acc_map[node.parent.path]['__children'].append(node_dict)
        else:
            final_tree.append(node_dict)
        acc_map[node.path] = node_dict

        return (acc_map, final_tree)

    if not grid.populated:
        grid.populate(visitor, final_output)
    else:
        grid.visit(node = None, function = visitor, initial_accumulator = final_output)

    outfd.write(json.dumps(final_output[0], indent = 2, sort_keys = True))
    outfd.close()
