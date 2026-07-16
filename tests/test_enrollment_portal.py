import http.client
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest


SOURCE=Path(__file__).parents[1]/"assets"/"vpn-enrollment-portal.py"
ENGINE=Path(__file__).parents[1]/"assets"/"vpn-enrollment-csr.py"
SPEC=importlib.util.spec_from_file_location("portal",SOURCE); portal=importlib.util.module_from_spec(SPEC)
assert SPEC.loader; SPEC.loader.exec_module(portal)


@unittest.skipUnless(shutil.which("openssl"),"OpenSSL unavailable")
class PortalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.store=portal.PublicStore(self.root/"spool",ENGINE)
        self.http=portal.ThreadingHTTPServer(("127.0.0.1",0),portal.PortalHandler)
        self.http.store=self.store; self.http.limiter=portal.RateLimiter(20,60)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True); self.thread.start()
        self.token="secret-token"; self.ident="a"*64; self.cn="vpn-player:11111111-1111-1111-1111-111111111111"
        self.bundle=b"PK\x03\x04"+b"encrypted-invitation-bundle"
        self.bundle_name="OpenVPN-LAN-Party-Arthur.zip"
        self.store.register({"id":self.ident,"token":self.token,"player":"Arthur",
                             "player_id":"player-id","credential_id":"11111111-1111-1111-1111-111111111111",
                             "certificate_cn":self.cn,
                             "security_mode":"high-assurance",
                             "expires_at":int(time.time())+900},
                            base64.b64encode(self.bundle).decode(),
                            hashlib.sha256(self.bundle).hexdigest(), self.bundle_name)
    def tearDown(self): self.http.shutdown(); self.http.server_close(); self.temp.cleanup()
    def request(self,method,path,body=None,token=None,headers=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.http.server_port)
        values={"Authorization":"Bearer "+(token or self.token)}; values.update(headers or {})
        if body is not None: body=json.dumps(body).encode(); values.update({"Content-Type":"application/json","Content-Length":str(len(body))})
        conn.request(method,path,body,values); response=conn.getresponse(); data=json.loads(response.read()); conn.close()
        return response.status,response.getheaders(),data
    def download(self,path):
        conn=http.client.HTTPConnection("127.0.0.1",self.http.server_port)
        conn.request("GET",path); response=conn.getresponse(); data=response.read(); headers=dict(response.getheaders()); conn.close()
        return response.status,headers,data
    def csr(self, cn=None):
        cn=cn or self.cn
        key=self.root/"key.pem"; csr=self.root/"request.pem"
        subprocess.run(["openssl","req","-new","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-nodes",
                        "-subj",f"/CN={cn}","-keyout",str(key),"-out",str(csr)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return csr.read_text()
    def test_challenge_submit_publish_and_single_collection(self):
        self.assertEqual([],self.store.pending_requests()["requests"])
        status,headers,bundle=self.download(f"/invitations/{self.ident}/{self.bundle_name}")
        self.assertEqual(200,status); self.assertEqual(self.bundle,bundle)
        self.assertEqual("application/zip",headers["Content-Type"])
        status,headers,value=self.request("GET","/api/v2/enrollments/challenge")
        self.assertEqual(200,status); self.assertEqual(self.cn,value["certificate_cn"])
        self.assertEqual(self.ident,value["enrollment_id"])
        self.assertEqual("11111111-1111-1111-1111-111111111111",value["credential_id"])
        self.assertEqual("high-assurance", value["security_mode"])
        self.assertEqual("no-store",dict(headers)["Cache-Control"])
        status,_,submitted=self.request("POST","/api/v2/enrollments",{"enrollment_id":self.ident,"csr":self.csr()})
        self.assertEqual(200,status); self.assertEqual("pending",submitted["state"])
        queue=self.store.pending_requests()
        self.assertEqual(1,queue["total"]); self.assertEqual(self.ident,queue["requests"][0]["id"])
        self.assertEqual(submitted["spki_sha256"],queue["requests"][0]["spki_sha256"])
        self.assertNotIn("csr",queue["requests"][0]); self.assertNotIn("token",queue["requests"][0])
        self.assertEqual("pending",self.store.status(self.ident)["state"])
        self.assertNotIn(self.token,(self.root/"spool"/f"{self.ident}.json").read_text())
        response={"certificate_pem":"CERT","tls_crypt_v2":"KEY","certificate_cn":self.cn,
                  "credential_id":"cred","player_id":"player","serial":"AB","kid":"kid",
                  "security_mode":"high-assurance"}
        self.store.publish(self.ident,response,submitted["spki_sha256"])
        repeated=self.store.publish(self.ident,response,submitted["spki_sha256"])
        self.assertEqual("approved",repeated["state"])
        changed=dict(response); changed["serial"]="AC"
        with self.assertRaises(portal.PortalError):
            self.store.publish(self.ident,changed,submitted["spki_sha256"])
        status,_,result=self.request("GET","/api/v2/enrollments/result")
        self.assertEqual(200,status); self.assertEqual("CERT",result["certificate_pem"])
        self.assertEqual(410,self.download(f"/invitations/{self.ident}/{self.bundle_name}")[0])
        status,_,_=self.request("GET","/api/v2/enrollments/result")
        self.assertEqual(410,status)

    def test_root_cancel_invalidates_token_bundle_and_pending_material(self):
        status,_,submitted=self.request(
            "POST","/api/v2/enrollments",{"enrollment_id":self.ident,"csr":self.csr()}
        )
        self.assertEqual(200,status)
        self.assertEqual("pending", submitted["state"])
        cancelled = self.store.cancel(self.ident)
        self.assertEqual("cancelled", cancelled["state"])
        self.assertEqual([], self.store.pending_requests()["requests"])
        self.assertEqual(410, self.download(f"/invitations/{self.ident}/{self.bundle_name}")[0])
        status,_,_=self.request("GET","/api/v2/enrollments/challenge")
        self.assertEqual(401,status)
        persisted=(self.root/"spool"/f"{self.ident}.json").read_text()
        self.assertNotIn("BEGIN CERTIFICATE REQUEST", persisted)
        self.assertNotIn(submitted["spki_sha256"], persisted)
        state=json.loads((self.root/"spool"/f"{self.ident}.json").read_text())
        self.assertNotIn("response",state); self.assertNotIn("csr",state)
    def test_auth_schema_size_and_replay_controls(self):
        self.assertEqual(401,self.request("GET","/api/v2/enrollments/challenge",token="wrong")[0])
        self.assertEqual(400,self.request("POST","/api/v2/enrollments",{"enrollment_id":self.ident,"csr":"bad","extra":1})[0])
        self.assertEqual(400,self.request("POST","/api/v2/enrollments",{"enrollment_id":7,"csr":[]})[0])
        self.assertEqual(413,self.request("POST","/api/v2/enrollments",None,headers={"Content-Type":"application/json","Content-Length":str(portal.MAX_JSON+1)})[0])
        csr=self.csr(); self.assertEqual(200,self.request("POST","/api/v2/enrollments",{"enrollment_id":self.ident,"csr":csr})[0])
        self.assertEqual(409,self.request("POST","/api/v2/enrollments",{"enrollment_id":self.ident,"csr":csr})[0])

    def test_pending_pool_keeps_simultaneous_invitations_isolated(self):
        first=self.store.submit(self.ident,self.token,self.csr())
        second_id="b"*64; second_token="second-secret-token"
        second_cn="vpn-player:22222222-2222-2222-2222-222222222222"
        self.store.register({"id":second_id,"token":second_token,"player":"Beatrice",
                             "player_id":"player-two","credential_id":"22222222-2222-2222-2222-222222222222",
                             "certificate_cn":second_cn,"security_mode":"high-assurance",
                             "expires_at":int(time.time())+900},
                            base64.b64encode(self.bundle).decode(),
                            hashlib.sha256(self.bundle).hexdigest(),self.bundle_name)
        second=self.store.submit(second_id,second_token,self.csr(second_cn))
        queue=self.store.pending_requests()
        self.assertEqual(2,queue["total"])
        self.assertEqual({self.ident,second_id},{request["id"] for request in queue["requests"]})
        response={"certificate_pem":"CERT","tls_crypt_v2":"KEY","certificate_cn":self.cn,
                  "credential_id":"cred","player_id":"player","serial":"AB","kid":"kid",
                  "security_mode":"high-assurance"}
        self.store.publish(self.ident,response,first["spki_sha256"])
        remaining=self.store.pending_requests()["requests"]
        self.assertEqual([second_id],[request["id"] for request in remaining])
        self.assertEqual(second["spki_sha256"],remaining[0]["spki_sha256"])
    def test_bundle_download_rejects_a_replaced_symlink(self):
        bundle_path=self.root/"spool"/f"{self.ident}.zip"
        target=self.root/"foreign"; target.write_bytes(self.bundle)
        bundle_path.unlink(); bundle_path.symlink_to(target)
        self.assertEqual(500,self.download(f"/invitations/{self.ident}/{self.bundle_name}")[0])
    def test_broker_admin_socket_is_bounded_and_owner_only(self):
        path=self.root/"admin.sock"; server=portal.AdminServer(str(path),self.store); self.assertEqual(0o600,path.stat().st_mode&0o777)
        thread=threading.Thread(target=server.handle_request,daemon=True); thread.start()
        client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); client.connect(str(path))
        client.sendall(json.dumps({"command":"inspect","id":self.ident}).encode()+b"\n")
        answer=json.loads(client.makefile("rb").readline()); client.close(); thread.join(2); server.server_close()
        self.assertFalse(answer["ok"])
    def test_rate_limit_and_expiry(self):
        limiter=portal.RateLimiter(1,60); self.assertTrue(limiter.allow("x")); self.assertFalse(limiter.allow("x"))
        expired="b"*64
        with self.assertRaises(portal.PortalError):
            self.store.register({"id":expired,"token":"x","player":"X","player_id":"p",
                                 "credential_id":"c","certificate_cn":"vpn-player:x",
                                 "security_mode":"compatible",
                                 "expires_at":int(time.time())-1},
                                base64.b64encode(self.bundle).decode(),
                                hashlib.sha256(self.bundle).hexdigest(), self.bundle_name)

    def test_loaded_public_validator_has_no_ca_or_openvpn_operations(self):
        source=ENGINE.read_text(encoding="utf-8")
        for forbidden in ("def approve", "ca_key", "easyrsa", "tls-crypt", "def begin_revoke"):
            self.assertNotIn(forbidden,source)


if __name__=="__main__": unittest.main()
