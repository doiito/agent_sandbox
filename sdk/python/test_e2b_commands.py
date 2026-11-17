import unittest
from types import SimpleNamespace
from osv_sandbox_client import (Sandbox, CommandEvent, JobResult, CommandExitException,
                                UnsupportedCapability, APIError, SessionCommand)
from test_client import result

class Native:
    def __init__(self, session, command):
        self.owner=session; self.command=command; self.id='c'*24
        self.pid=42;self.killed=False;self.finished=False;self.iterations=0
    def poll(self):return {'info':self.info(), 'complete':self.finished}
    def info(self):return {'id':self.id,'session_id':self.owner.id,'pid':42,'state':'succeeded' if self.finished else 'running',
                          'entrypoint':self.command.entrypoint,'args':list(self.command.args),
                          'environment':self.command.environment,'cwd':self.command.cwd}
    def kill(self):
        accepted=not self.killed and not self.finished; self.killed=True; return accepted
    def events(self, after=0, *, timeout_ms=None):
        self.iterations+=1
        yield CommandEvent(1,'stdout',b'ok\xe2')
        yield CommandEvent(2,'stderr',b'warning')
        yield CommandEvent(3,'stdout',b'\x82\xac')
        value=result();value['id']=self.id
        if 'exit 7' in self.command.args[-1]:value.update(state='guest_error',exit_code=7)
        self.finished=True
        yield CommandEvent(3,result=JobResult.from_payload(value))

class FakeSession:
    id='b'*24
    def __init__(self):
        self.created=SimpleNamespace(backend='firecracker-linux',artifact_manifest_sha256='a'*64)
        self._client=SimpleNamespace(capabilities=lambda **kwargs:{'allowed_entrypoints':['/bin/bash'],'limits':{'max_timeout_ms':30000}})
        self.commands=[]
    def start_command(self,command):
        command.payload()
        item=Native(self,command);self.commands.append(item);return item
    def list_commands(self):return [c.info() for c in self.commands]

class E2BCommandTests(unittest.TestCase):
    def test_bash_environment_workdir_callbacks_and_cached_wait(self):
        session=FakeSession();sandbox=Sandbox(session);out=[];err=[]
        handle=sandbox.commands.run('printf test',background=True,envs={'KEY':'value'},cwd='/workspace/sub')
        self.assertEqual(handle.pid,42)
        running=sandbox.commands.list()[0]
        self.assertEqual((running.cmd,running.envs,running.cwd),('/bin/bash',{'KEY':'value'},'/workspace/sub'))
        final=handle.wait(on_stdout=out.append,on_stderr=err.append)
        self.assertEqual((final.stdout,final.stderr,final.exit_code),('ok€','warning',0))
        self.assertIs(handle.wait(on_stdout=out.append),final)
        self.assertEqual(out,['ok','€'])
        self.assertEqual(session.commands[0].iterations,1)
        self.assertEqual(sandbox.commands.list(),[])

    def test_nonzero_exit_has_public_result_fields_and_does_not_reexecute(self):
        session=FakeSession();sandbox=Sandbox(session)
        handle=sandbox.commands.run('exit 7',background=True)
        for _ in range(2):
            with self.assertRaises(CommandExitException) as caught:handle.wait()
            self.assertEqual((caught.exception.exit_code,caught.exception.stdout,caught.exception.stderr),(7,'ok€','warning'))
        self.assertEqual(session.commands[0].iterations,1)
        self.assertFalse(sandbox.commands.kill(999))
        with self.assertRaises(APIError):sandbox.commands.connect(999)

    def test_unavailable_options_and_invalid_environment_fail_before_start(self):
        session=FakeSession();sandbox=Sandbox(session)
        for options in ({'stdin':True},{'user':'root'},{'background':True,'on_stdout':print}):
            with self.assertRaises(UnsupportedCapability):sandbox.commands.run('printf forbidden',**options)
        self.assertEqual(session.commands,[])
        from osv_sandbox_client import ConfigurationError
        for env in ({'bad key':'x'},{'A':'x'*1025}):
            with self.assertRaises(ConfigurationError):SessionCommand('/bin/bash',environment=env).payload()

if __name__=='__main__':unittest.main()

class DisconnectTests(unittest.TestCase):
    def test_disconnect_in_output_callback_stops_observation_without_kill(self):
        from osv_sandbox_client import TransportError
        session = FakeSession()
        handle = Sandbox(session).commands.run('printf test', background=True)
        seen = []
        def output(text):
            seen.append(text)
            handle.disconnect()
        with self.assertRaises(TransportError):
            handle.wait(on_stdout=output)
        self.assertEqual(seen, ['ok'])
        self.assertFalse(session.commands[0].killed)
        self.assertFalse(session.commands[0].finished)
