from flask import Flask, Blueprint, current_app
from flask_restful import Api, Resource
import sys, json, os, response
from os import path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../volatility3'))
import volatility
from volatility.plugins import windows, mac, linux
from volatility.plugins.windows import pslist, pstree, filescan, netscan
from volatility.plugins.mac import pslist, pstree
from volatility.plugins.linux import pslist, pstree
from volatility import framework
from volatility.framework import contexts, automagic, exceptions, plugins, interfaces
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from utils.parser import _type_renderers, PrintedProgress, file_handler_class_factory, process_unsatisfied_exceptions
from typing import Dict, Type, Union, Any, List, Tuple

volatility_api = Blueprint('volatility_api', __name__,  static_folder="static")

with open(path.realpath(os.path.join(os.path.dirname(__file__), 'volatility_plugins.json')), 'r') as json_file:
    current_app.config['plugins_list'] = json.load(json_file)


@volatility_api.route("/<os_name>/<plugin_name>")
def run_plugin(os_name, plugin_name):
    
    dump_path = os.environ.get("DUMP_PATH")
    
    framework.require_interface_version(2, 0, 0)
    ctx = contexts.Context()
    config_path = interfaces.configuration.path_join('automagic', 'LayerStacker', 'single_location')
    ctx.config['automagic.LayerStacker.single_location'] = 'file:'+dump_path

    unsatisfied = interfaces.plugins.PluginInterface.unsatisfied(ctx, config_path)

    automagics = automagic.available(ctx)
    automagics = automagic.choose_automagic(automagics, eval(current_app.config['plugins_list'][os_name][plugin_name]))
    constructed = None
    try:
        progress_callback = PrintedProgress()
        constructed = plugins.construct_plugin(ctx, automagics, eval(current_app.config['plugins_list'][os_name][plugin_name]), config_path, progress_callback, file_handler_class_factory(dump_path))
    except exceptions.UnsatisfiedException as excp:
                err_msg = process_unsatisfied_exceptions(excp)
                return{"err_msg": err_msg}
    if constructed is not None:
        grid = constructed.run()

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
            
        return {'data': final_output[0]}
    else:
        return {'err-message':"Errore nella costruzione del plugin"+os_name+"."+plugin_name+". Controllare di aver inserito un file valido e non corrotto."}