import rex
import nose
import pickle

import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
tests_dir = str(os.path.dirname(os.path.realpath(__file__)))


def _load_cache(bin_name):
    path = os.path.join(tests_dir, "rop_cache", bin_name+".rop")
    cache_tuple = pickle.load(open(path, "rb"))
    return cache_tuple

def test_write_what_where_shadowstack():
    """
    Test that our write what where exploit can leak, and works in the presence of a shadowstack
    """
    crash_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    rop_cache = _load_cache("write_what_where_shadow_stack")
    crash = rex.Crash(os.path.join(bin_location + "/tests/i386/write_what_where_shadow_stack"), crash_str,
                      rop_cache_tuple=rop_cache)
    arsenal = crash.exploit()
    exploit = arsenal.best_type2
    nose.tools.assert_true(exploit.test_binary())

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
