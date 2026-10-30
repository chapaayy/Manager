"""Run with: python -m unittest discover -s tests -v"""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('xppn_helper',ROOT/'agent/helper.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)

class HelperTests(unittest.TestCase):
    def test_whitelist_no_shell(self):
        with self.assertRaises(PermissionError): helper.execute({'command':'shell','payload':{'command':'rm -rf /'}})
        with self.assertRaises(PermissionError): helper.execute({'command':'docker.action','payload':{'container':'xppn-agent','action':'stop'}})
        with self.assertRaises(PermissionError): helper.execute({'command':'config.read','payload':{'name':'/etc/shadow'}})
    def test_edits_have_sha_guard_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=pathlib.Path(tmp);f=base/'nginx.conf';f.write_text('old config')
            with patch.dict(helper.ALLOWED,{'nginx':f}),patch.object(helper,'backup',lambda *args:base/'saved'),patch.object(helper,'validate_config',return_value='ok'),patch.object(helper,'run',return_value='ok'):
                good=helper.save_config({'name':'nginx','content':'new config','sha256':helper.digest('old config')})
                self.assertEqual(f.read_text(),'new config')
                self.assertEqual(good['sha256'],helper.digest('new config'))
                with self.assertRaises(ValueError):helper.save_config({'name':'nginx','content':'wrong','sha256':helper.digest('old config')})
                with patch.object(helper,'validate_config',side_effect=RuntimeError('invalid')):
                    with self.assertRaises(RuntimeError):helper.save_config({'name':'nginx','content':'bad config','sha256':helper.digest('new config')})
                self.assertEqual(f.read_text(),'new config')
    def test_symlink_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=pathlib.Path(tmp);target=base/'target';target.write_text('hello')
            link=base/'link';link.symlink_to(target)
            with self.assertRaises(ValueError):helper.assert_file(link)
    def test_version_input(self):
        with self.assertRaises(ValueError):helper.upgrade_node({'version':'latest;touch /root/pwn'})

if __name__=='__main__':unittest.main()

class SignedInstructionTests(unittest.TestCase):
    def test_replay_and_tampering_blocked(self):
        import time,hmac,hashlib,json,uuid
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)
            (root/'key').write_text('a'*64)
            original=helper.Path
            def redirect(s):
                if s=='/opt/xppn-agent/helper.key':return root/'key'
                if s=='/var/lib/xppn-helper':return root/'replay'
                return original(s)
            instruction={'job_id':str(uuid.uuid4()),'command':'docker.logs','payload':{'container':'nginx'},'expires':int(time.time())+900}
            msg=json.dumps(instruction,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
            signature=hmac.new(bytes.fromhex('a'*64),msg,hashlib.sha256).hexdigest()
            request={'command':'docker.logs','payload':{'container':'nginx'},'signed':instruction,'signature':signature}
            with patch.object(helper,'Path',redirect),patch.object(helper,'run',return_value='nginx logs'):
                modified={**request,'payload':{'container':'remnanode'}}
                with self.assertRaises(PermissionError):helper.execute(modified)
                self.assertEqual(helper.execute(request),'nginx logs')
                with self.assertRaises(PermissionError):helper.execute(request)
