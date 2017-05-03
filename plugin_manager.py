import os, importlib, sys

plug_handler=None

hooks_str={'on_load',
        'on_found_device',
        'on_try_auth',
        'on_auth_succeed',
        'on_auth_failed',
        'on_deauth',
        'on_offline'}

class plugman:
    plugins=[]
    hooks={
        'on_load':[],
        'on_found_device':[],
        'on_try_auth':[],
        'on_auth_succeed':[],
        'on_auth_failed':[],
        'on_deauth':[],
        'on_offline':[]
    }
    def __init__(self):
        path=os.path.split(sys.argv[0])[:-1][0]+'/plugins'
        for parent, dirname, filename in os.walk(path):
            for file in filename:
                if file[-3:]=='.py':
                    file_path = os.path.join(parent, file)
                    mod=importlib.import_module('plg.'+file[:-3])
                    self.plugins.append(mod)
                    for hook in hooks_str:
                        if hasattr(mod,hook):
                            self.hooks[hook].append(getattr(mod,hook))

    def onevent(self,ev_str,ev_obj):
        ret=[]
        for func in self.hooks[ev_str]:
            ret.append(func(ev_obj))
        return ret

