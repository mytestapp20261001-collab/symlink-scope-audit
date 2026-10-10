import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location("audit_tool",Path(__file__).with_name("tool.py"))
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def codes(self,result):return {x["code"] for x in result.get("findings",[])}
    def call(self,*args):
        result=subprocess.run([sys.executable,str(Path(__file__).with_name("tool.py")),*map(str,args)],capture_output=True,text=True)
        return result.returncode,json.loads(result.stdout)
    def test_bad_cli(self):
        code,result=self.call("--unknown");self.assertEqual(code,2);self.assertEqual(result["status"],"error")
    def test_examples(self):
        result=subprocess.run([sys.executable,str(Path(__file__).parent/"examples"/"run_examples.py")],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        reports=[json.loads(x) for x in result.stdout.splitlines()]
        self.assertEqual([r["status"] for r in reports],["pass","findings"])

    def test_internal_and_cli(self):
        (self.root/'a').write_text('not read');(self.root/'link').symlink_to('a')
        r=tool.audit(self.root);self.assertEqual(r['status'],'pass');self.assertEqual(r['summary']['links_checked'],1);self.assertEqual(self.call(self.root)[0],0)
    def test_outside_and_dangling(self):
        (self.root/'out').symlink_to('../secret');(self.root/'dangling').symlink_to('absent')
        r=tool.audit(self.root);self.assertEqual(self.codes(r),{'outside_scope','dangling_link'});self.assertEqual(self.call(self.root)[0],1)
        self.assertNotIn('secret',json.dumps(r))
    def test_cycles_and_hop_limit(self):
        (self.root/'a').symlink_to('b');(self.root/'b').symlink_to('a')
        self.assertIn('symlink_cycle',self.codes(tool.audit(self.root)));self.assertIn('link_hop_limit_exceeded',self.codes(tool.audit(self.root,max_hops=1)))
    def test_absolute_internal_and_directory_chain(self):
        d=self.root/'dir';d.mkdir();(d/'f').touch();(self.root/'a').symlink_to(str(d));(self.root/'b').symlink_to('a/f')
        self.assertEqual(tool.audit(self.root)['status'],'pass')
    def test_parent_after_link_and_nondirectory(self):
        (self.root/'d').mkdir();(self.root/'a').symlink_to('d');(self.root/'file').touch();(self.root/'good').symlink_to('a/../file');(self.root/'bad').symlink_to('file/../file')
        r=tool.audit(self.root);self.assertEqual(self.codes(r),{'non_directory_component'});self.assertEqual(r['findings'][0]['path'],'bad')
    def test_external_link_never_probed(self):
        (self.root/'out').symlink_to('/definitely-outside-do-not-open')
        with mock.patch.object(tool.os,'readlink',wraps=os.readlink) as read:
            r=tool.audit(self.root);self.assertEqual(self.codes(r),{'outside_scope'});self.assertEqual(read.call_count,1)
    def test_limits_and_permissions(self):
        (self.root/'a').touch();(self.root/'b').touch();self.assertEqual(tool.audit(self.root,max_entries=1)['status'],'error')
        with mock.patch.object(tool,'walk',side_effect=PermissionError):self.assertEqual(tool.audit(self.root)['status'],'error')

    def test_support_rejects_symlink_before_dotdot(self):
        import _support
        (self.root/'actual').mkdir();(self.root/'alias').symlink_to('actual');(self.root/'safe').write_bytes(b'x')
        with self.assertRaises((OSError,_support.InputError)):
            with _support.anchored(str(self.root)+'/alias/../safe'):
                self.fail('must not normalize away a symlink component')
    def test_support_detects_pre_read_mutation(self):
        import _support
        p=self.root/'changed';p.write_bytes(b'a');before=p.stat();p.write_bytes(b'longer')
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):_support.read_at(fd,'changed',before,100)
    def test_support_entry_budget_and_host_guard(self):
        import _support
        (self.root/'a').mkdir();(self.root/'a'/'x').touch();(self.root/'b').touch()
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):list(_support.walk(fd,max_entries=2))
        with mock.patch.object(_support.os,'name','unsupported'):
            with self.assertRaises(_support.InputError):_support._flags()


    def test_absolute_internal_redundant_prefix_components(self):
        (self.root/'file').touch()
        for index,prefix in enumerate((str(self.root).replace('/','//'),str(self.root).replace('/','/./'))):
            (self.root/('link'+str(index))).symlink_to(prefix+'/file')
        self.assertEqual(tool.audit(self.root)['status'],'pass');self.assertEqual(self.call(self.root)[0],0)

    def test_absolute_suffix_preserves_directory_requirements(self):
        (self.root/'file').touch();(self.root/'dir').mkdir()
        (self.root/'good').symlink_to(str(self.root)+'/dir/../file')
        (self.root/'bad-dot').symlink_to(str(self.root)+'/file/.')
        (self.root/'bad-slash').symlink_to(str(self.root)+'/file/')
        r=tool.audit(self.root)
        self.assertEqual({f['path'] for f in r['findings']},{'bad-dot','bad-slash'})
        self.assertEqual(self.codes(r),{'non_directory_component'})

    def test_absolute_prefix_does_not_normalize_dotdot_or_links(self):
        (self.root/'file').touch();(self.root/'out').symlink_to('../outside')
        (self.root/'chain').symlink_to(str(self.root)+'/out/../file')
        (self.root/'escape-return').symlink_to(str(self.root)+'/../'+self.root.name+'/file')
        r=tool.audit(self.root);self.assertEqual(self.codes(r),{'outside_scope'})
        self.assertEqual({f['path'] for f in r['findings']},{'out','chain','escape-return'})

if __name__=="__main__":unittest.main()
