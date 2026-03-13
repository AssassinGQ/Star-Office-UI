#!/usr/bin/env python3
"""
OpenClaw WebSocket客户端 - 修复版
修复：协议格式、Token传递、设备配对、自动重连

协议格式说明：
- 消息需要使用请求帧格式: { type: "req", method: "...", id: "...", params: {...} }
- 第一帧必须是 method: "connect"
- connect params 中需要包含: minProtocol, maxProtocol, client, device(设备签名)
"""

import asyncio
import json
import uuid
import sys
import os
import urllib.parse
import base64
import hashlib
import hmac
from datetime import datetime
from typing import Optional, Callable, Dict, Any
import websockets
from websockets.exceptions import ConnectionClosed
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


# 协议版本
PROTOCOL_VERSION = 3

# 设备ID和私钥（从 ~/.openclaw/identity/device.json 获取）
# 现在改为动态生成密钥对

def generate_keypair():
    """生成 Ed25519 密钥对"""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    
    ED25519_SPKI_PREFIX = bytes([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])  # 12 bytes
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    # 计算 deviceId - 需要去除 SPKI prefix
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # 去除前12字节的 SPKI prefix
    public_raw = public_der[len(ED25519_SPKI_PREFIX):]
    device_id = hashlib.sha256(public_raw).hexdigest()
    
    # 转换为 base64url 格式 - 也是去除 SPKI prefix
    public_b64url = base64.urlsafe_b64encode(public_raw).decode().rstrip('=')
    
    return {
        "device_id": device_id,
        "private_key": private_pem,
        "public_key": public_b64url,
    }


# 尝试加载已保存的密钥，或生成新的
KEYPAIR_FILE = os.path.expanduser("~/.openclaw/python-client-identity.json")

def load_or_create_keypair():
    """加载或创建密钥对"""
    if os.path.exists(KEYPAIR_FILE):
        with open(KEYPAIR_FILE, "r") as f:
            return json.load(f)
    
    # 生成新密钥
    keypair = generate_keypair()
    
    # 保存
    os.makedirs(os.path.dirname(KEYPAIR_FILE), exist_ok=True)
    with open(KEYPAIR_FILE, "w") as f:
        json.dump(keypair, f)
    os.chmod(KEYPAIR_FILE, 0o600)
    
    return keypair


# 加载密钥
KEYPAIR = load_or_create_keypair()
DEVICE_ID = KEYPAIR["device_id"]
DEVICE_PRIVATE_KEY = KEYPAIR["private_key"]
DEVICE_PUBLIC_KEY = KEYPAIR["public_key"]

print(f"📱 设备ID: {DEVICE_ID}")
print(f"📱 公钥: {DEVICE_PUBLIC_KEY[:40]}...")


def sign_payload(payload: str, private_key_pem: str) -> str:
    """使用Ed25519私钥对载荷进行签名"""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    # Ed25519签名
    signature = private_key.sign(payload.encode())
    
    return base64.urlsafe_b64encode(signature).decode().rstrip('=')


def build_device_auth_payload(
    device_id: str,
    client_id: str,
    client_mode: str,
    role: str,
    scopes: list,
    signed_at_ms: int,
    nonce: str,
    token: str = ""
) -> str:
    """构建设备认证载荷 (v2格式，与前端一致)"""
    scopes_str = ",".join(scopes)
    # 前端代码使用 v2 格式！
    parts = [
        "v2",  # 使用v2，不是v3
        device_id,
        client_id,
        client_mode,
        role,
        scopes_str,
        str(signed_at_ms),
        token,  # 空字符串就是空字符串
        nonce,
    ]
    return "|".join(parts)


class OpenClawWebSocketClient:
    def __init__(self, uri: str = "ws://localhost:18789", token: str = None):
        self.base_uri = uri
        self.token = token
        self.uri = uri  # Token不放在URL中，在connect params中传递
        
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.connected = False
        self.authenticated = False
        self.session_id: Optional[str] = None
        self.message_counter = 0
        self.pending_responses: Dict[str, asyncio.Future] = {}
        self.event_handlers: Dict[str, Callable] = {}
        self.receive_task: Optional[asyncio.Task] = None
        self.device_id = DEVICE_ID  # 使用全局的设备ID
        self.client_id = "cli"  # 客户端ID（必须是有效的client id）
        
        # 初始化用于设备认证的变量
        self._challenge_nonce = None
        self._initial_nonce = None
        self._initial_signed_at = None
        self._initial_scopes = None
        self._hello_ok_received = False
        self._last_error = None
        
    def _generate_id(self) -> str:
        """生成唯一消息ID"""
        self.message_counter += 1
        return f"msg-{self.message_counter}-{uuid.uuid4().hex[:8]}"
    
    def _generate_session_id(self) -> str:
        """生成唯一Session ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_hex = uuid.uuid4().hex[:4]
        return f"sess-{timestamp}-{random_hex}"
    
    async def connect(self) -> bool:
        """建立WebSocket连接并认证"""
        try:
            print(f"🔌 连接到 {self.base_uri}...")
            print(f"📝 设备ID: {self.device_id}")
            
            # 连接 - 添加Origin header
            self.websocket = await websockets.connect(
                self.uri,
                ping_interval=20,
                ping_timeout=10,
                additional_headers={
                    "Origin": "http://localhost:18789",
                }
            )
            self.connected = True
            print("✅ WebSocket连接成功")
            
            # 启动接收循环
            self.receive_task = asyncio.create_task(self._receive_loop())
            
            # 等待获取challenge nonce
            await asyncio.sleep(0.5)
            
            # 发送带device的connect请求
            auth_success = await self._send_connect_with_device_and_token()
                
            if auth_success:
                self.authenticated = True
                print("✅ 认证成功")
                return True
            else:
                print("❌ 认证失败")
                await self.disconnect()
                return False
                
        except Exception as e:
            print(f"❌ 连接错误: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def _send_connect_with_device_and_token(self) -> bool:
        """发送connect请求 - 同时发送token和device（服务器会从auth.token获取签名token）"""
        import time
        
        nonce = self._challenge_nonce or ""
        signed_at_ms = int(time.time() * 1000)
        
        scopes = ["operator.admin", "operator.approvals", "operator.pairing"]
        
        # 关键：服务器会从 auth.token 获取签名token，所以这里用 self.token
        payload = build_device_auth_payload(
            device_id=DEVICE_ID,
            client_id="cli",
            client_mode="cli",
            role="operator",
            scopes=scopes,
            signed_at_ms=signed_at_ms,
            nonce=nonce,
            token=self.token  # 使用auth.token的值
        )
        
        print(f"🔐 签名载荷: {payload}")
        
        signature = sign_payload(payload, DEVICE_PRIVATE_KEY)
        
        # 同时发送 token 和 device
        connect_params = {
            "minProtocol": PROTOCOL_VERSION,
            "maxProtocol": PROTOCOL_VERSION,
            "client": {
                "id": "cli",
                "displayName": "Python-WebSocket-Client",
                "version": "1.0.0",
                "platform": "python",
                "mode": "cli",
            },
            "scopes": scopes,
            "role": "operator",
            "auth": {
                "token": self.token,
            },
            "device": {
                "id": DEVICE_ID,
                "publicKey": DEVICE_PUBLIC_KEY,
                "signature": signature,
                "signedAt": signed_at_ms,
                "nonce": nonce,
            },
        }
        
        connect_msg = {
            "type": "req",
            "method": "connect",
            "id": self._generate_id(),
            "params": connect_params
        }
        
        print(f"📤 发送connect（token+device）: {json.dumps(connect_msg)[:200]}...")
        
        self._initial_scopes = scopes
        
        try:
            await self.websocket.send(json.dumps(connect_msg))
            await asyncio.sleep(2)
            
            # 检查是否收到 hello-ok
            if hasattr(self, '_hello_ok_received') and self._hello_ok_received:
                print(f"✅ 收到hello-ok！")
                return True
            
            # 检查是否收到配对请求错误
            if hasattr(self, '_last_error') and self._last_error:
                error = self._last_error
                if error.get("code") in ["NOT_PAIRED", "PAIRING_REQUIRED"]:
                    request_id = error.get("details", {}).get("requestId")
                    if request_id:
                        print(f"🔗 需要配对设备！requestId: {request_id}")
                        print(f"📋 请在 Gateway 上运行以下命令批准配对:")
                        print(f"   openclaw devices approve {request_id}")
                        
                        # 等待用户批准
                        input("   按回车键继续（批准配对后）...")
                        
                        # 重新连接
                        print(f"🔄 重新连接...")
                        await self.disconnect()
                        return await self.connect()
            
            return True
        except Exception as e:
            print(f"❌ Connect错误: {e}")
            return False
    
    async def _send_device_auth(self) -> bool:
        """发送device认证请求"""
        import time
        
        nonce = self._challenge_nonce or uuid.uuid4().hex
        signed_at_ms = int(time.time() * 1000)
        
        scopes = ["operator.admin", "operator.approvals", "operator.pairing"]
        
        # 构建载荷
        payload = build_device_auth_payload(
            device_id=DEVICE_ID,
            client_id="cli",
            client_mode="cli",
            role="operator",
            scopes=scopes,
            signed_at_ms=signed_at_ms,
            nonce=nonce,
            token=""
        )
        
        signature = sign_payload(payload, DEVICE_PRIVATE_KEY)
        
        # 发送device认证请求
        auth_msg = {
            "type": "req",
            "method": "device.auth",
            "id": self._generate_id(),
            "params": {
                "device": {
                    "id": DEVICE_ID,
                    "publicKey": DEVICE_PUBLIC_KEY,
                    "signature": signature,
                    "signedAt": signed_at_ms,
                    "nonce": nonce,
                },
                "role": "operator",
                "scopes": scopes,
            }
        }
        
        print(f"📤 发送device认证: {json.dumps(auth_msg)[:200]}...")
        
        try:
            await self.websocket.send(json.dumps(auth_msg))
            await asyncio.sleep(1)
            return True
        except Exception as e:
            print(f"❌ 设备认证错误: {e}")
            return False
    
    async def _send_connect(self) -> bool:
        """
        发送connect请求 - 同时发送共享token和device (使用服务器nonce)
        """
        import time
        
        # 获取服务器nonce
        if not hasattr(self, '_challenge_nonce') or not self._challenge_nonce:
            print("⚠️ 没有challenge nonce，先发送不带device的请求")
            return await self._connect_without_device()
        
        nonce = self._challenge_nonce
        signed_at_ms = int(time.time() * 1000)
        
        scopes = ["operator.admin", "operator.read", "operator.write"]
        
        # 用共享token + 服务器nonce构建载荷并签名
        payload = build_device_auth_payload(
            device_id=DEVICE_ID,
            client_id="cli",
            client_mode="cli",
            role="operator",
            scopes=scopes,
            signed_at_ms=signed_at_ms,
            nonce=nonce,
            token=self.token or ""
        )
        
        signature = sign_payload(payload, DEVICE_PRIVATE_KEY)
        
        # 构建connect params（带共享token + device）
        connect_params = {
            "minProtocol": PROTOCOL_VERSION,
            "maxProtocol": PROTOCOL_VERSION,
            "client": {
                "id": "cli",
                "displayName": "Python-WebSocket-Client",
                "version": "1.0.0",
                "platform": "python",
                "mode": "cli",
            },
            "scopes": scopes,
            "role": "operator",
            "auth": {
                "token": self.token,
            },
            "device": {
                "id": DEVICE_ID,
                "publicKey": DEVICE_PUBLIC_KEY,
                "signature": signature,
                "signedAt": signed_at_ms,
                "nonce": nonce,
            },
        }
        
        # 构建请求帧
        connect_msg = {
            "type": "req",
            "method": "connect",
            "id": self._generate_id(),
            "params": connect_params
        }
        
        print(f"📤 发送connect请求（token+device）: {json.dumps(connect_msg)[:200]}...")
        
        self._initial_scopes = scopes
        
        try:
            await self.websocket.send(json.dumps(connect_msg))
            
            # 等待响应
            await asyncio.sleep(1.5)
            
            # 检查是否收到hello-ok
            if hasattr(self, '_hello_ok_received') and self._hello_ok_received:
                print(f"✅ 收到hello-ok，连接成功！")
                return True
            
            return True
                
        except Exception as e:
            print(f"❌ Connect错误: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def _connect_without_device(self) -> bool:
        """不带device的连接"""
        import time
        
        scopes = ["operator.admin", "operator.read", "operator.write"]
        
        connect_params = {
            "minProtocol": PROTOCOL_VERSION,
            "maxProtocol": PROTOCOL_VERSION,
            "client": {
                "id": "cli",
                "displayName": "Python-WebSocket-Client",
                "version": "1.0.0",
                "platform": "python",
                "mode": "cli",
            },
            "role": "operator",
            "auth": {
                "token": self.token,
            }
        }
        
        connect_msg = {
            "type": "req",
            "method": "connect",
            "id": self._generate_id(),
            "params": connect_params
        }
        
        print(f"📤 发送connect请求（仅token）: {json.dumps(connect_msg)[:200]}...")
        
        self._initial_scopes = scopes
        
        try:
            await self.websocket.send(json.dumps(connect_msg))
            
            await asyncio.sleep(1.5)
            
            return True
                
        except Exception as e:
            print(f"❌ Connect错误: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def _send_device_auth_after_hello(self) -> bool:
        """在hello-ok后发送设备认证"""
        import time
        
        nonce = self._challenge_nonce or uuid.uuid4().hex
        signed_at_ms = int(time.time() * 1000)
        
        scopes = self._initial_scopes
        
        # 构建设备载荷
        payload = build_device_auth_payload(
            device_id=DEVICE_ID,
            client_id="cli",
            client_mode="cli",
            role="operator",
            scopes=scopes,
            signed_at_ms=signed_at_ms,
            nonce=nonce,
            token=self.token or ""
        )
        
        signature = sign_payload(payload, DEVICE_PRIVATE_KEY)
        
        # 发送device认证请求
        auth_msg = {
            "type": "req",
            "method": "device.auth",
            "id": self._generate_id(),
            "params": {
                "device": {
                    "id": DEVICE_ID,
                    "publicKey": DEVICE_PUBLIC_KEY,
                    "signature": signature,
                    "signedAt": signed_at_ms,
                    "nonce": nonce,
                },
                "role": "operator",
                "scopes": scopes,
            }
        }
        
        print(f"📤 发送device认证: {json.dumps(auth_msg)[:200]}...")
        
        try:
            await self.websocket.send(json.dumps(auth_msg))
            await asyncio.sleep(1)
            return True
        except Exception as e:
            print(f"❌ 设备认证错误: {e}")
            return False
    
    async def _receive_loop(self):
        """后台接收循环"""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message)
                    print(f"📥 收到消息: {json.dumps(data)[:200]}")  # 调试日志
                    await self._handle_message(data)
                except json.JSONDecodeError:
                    print(f"⚠️ 收到非JSON消息: {message[:100]}")
        except ConnectionClosed as e:
            print(f"🔌 连接已关闭 (code: {e.code}, reason: {e.reason})")
            self.connected = False
            self.authenticated = False
        except Exception as e:
            print(f"❌ 接收循环错误: {e}")
            self.connected = False
    
    async def _handle_message(self, data: Dict[str, Any]):
        """处理收到的消息"""
        msg_type = data.get("type")
        msg_id = data.get("id")
        method = data.get("method")
        
        # 1. 捕获 challenge 事件，提取nonce
        if msg_type == "event" and data.get("event") == "connect.challenge":
            payload = data.get("payload", {})
            self._challenge_nonce = payload.get("nonce")
            print(f"📝 收到challenge，nonce: {self._challenge_nonce}")
            return
        
        # 2. 处理响应帧中的错误（connect 失败）
        if msg_type == "res" and data.get("ok") == False:
            error = data.get("error", {})
            print(f"❌ 收到错误响应: {error}")
            self._last_error = error
            # 也设置 pending response 以便调用者检查
            if msg_id and msg_id in self.pending_responses:
                future = self.pending_responses.pop(msg_id)
                if not future.done():
                    future.set_result(data)
            return
        
        # 3. 处理响应帧中的 hello-ok
        if msg_type == "res" and data.get("ok") == True:
            payload = data.get("payload", {})
            if payload.get("type") == "hello-ok":
                print(f"✅ 收到 hello-ok: auth={payload.get('auth')}")
                # 检查是否有deviceToken
                auth_info = payload.get("auth", {})
                if auth_info.get("deviceToken"):
                    print(f"✅ 收到deviceToken: {auth_info.get('deviceToken')}")
                    print(f"✅ scopes: {auth_info.get('scopes')}")
                else:
                    print(f"⚠️ 没有收到deviceToken！")
                self._hello_ok_received = True
                # 继续处理pending的响应
                if msg_id and msg_id in self.pending_responses:
                    future = self.pending_responses.pop(msg_id)
                    if not future.done():
                        future.set_result(data)
                return
        
        # 2. 处理 hello-ok 响应（旧格式，可能不用）
        if msg_type == "hello-ok":
            print(f"✅ 收到 hello-ok: {json.dumps(data)[:300]}")
            self._hello_ok_received = True
            if msg_id and msg_id in self.pending_responses:
                future = self.pending_responses.pop(msg_id)
                if not future.done():
                    future.set_result(data)
            return
        
        # 3. 处理响应（匹配pending的请求）
        if msg_id and msg_id in self.pending_responses:
            future = self.pending_responses.pop(msg_id)
            if not future.done():
                future.set_result(data)
            return
        
        # 3. 处理服务器主动推送的事件
        if method:
            handler = self.event_handlers.get(method)
            if handler:
                await handler(data.get("params", {}))
            else:
                # 打印未知事件（调试用）
                if method not in ["ping", "pong"]:  # 忽略心跳
                    print(f"📨 收到推送 [{method}]")
    
    async def create_session(self, description: str = "WebSocket Session") -> str:
        """创建新Session"""
        # 使用正确的 sessionKey 格式: agent:agentId:chat
        self.session_id = "agent:default:chat"
        
        print(f"🆕 创建Session: {self.session_id}")
        
        # 通过发送第一条消息隐式创建Session
        init_msg = {
            "type": "req",
            "id": self._generate_id(),
            "method": "chat.send",
            "params": {
                "sessionKey": self.session_id,
                "message": f"Hello from Python WebSocket Client",
                "idempotencyKey": self._generate_id(),
            }
        }
        
        response = await self._send_and_wait(init_msg, timeout=30.0)
        if response and response.get("ok"):
            print(f"✅ Session创建成功")
            return self.session_id
        else:
            error = response.get("error", "未知错误") if response else "无响应"
            print(f"❌ Session创建失败: {error}")
            return None
    
    async def chat(self, message: str, stream: bool = True) -> str:
        """发送对话消息"""
        if not self.session_id:
            print("❌ 请先调用create_session()创建Session")
            return None
        
        chat_msg = {
            "type": "req",
            "id": self._generate_id(),
            "method": "chat.send",
            "params": {
                "sessionKey": self.session_id,
                "message": message,
                "idempotencyKey": self._generate_id(),
            }
        }
        
        print(f"\n👤 You: {message}")
        
        if stream:
            print("🤖 Assistant: ", end="", flush=True)
            full_content = []
            
            # 注册流式处理器
            async def handle_stream(params):
                chunk = params.get("content", "")
                if chunk:
                    print(chunk, end="", flush=True)
                    full_content.append(chunk)
                if params.get("finish_reason"):
                    print()  # 换行
            
            self.event_handlers["chat.stream"] = handle_stream
            
            # 发送消息
            await self.websocket.send(json.dumps(chat_msg))
            
            # 等待流完成（简化处理）
            await asyncio.sleep(2.0)
            
            self.event_handlers.pop("chat.stream", None)
            return "".join(full_content)
        else:
            print("🤖 Assistant: ", end="", flush=True)
            response = await self._send_and_wait(chat_msg, timeout=30.0)
            if response and response.get("ok"):
                content = response.get("payload", {}).get("content", "")
                print(content)
                return content
            else:
                error = response.get("error", "未知错误") if response else "无响应"
                print(f"❌ 请求失败: {error}")
                return None
    
    async def _send_and_wait(self, message: Dict, timeout: float = 30.0) -> Optional[Dict]:
        """发送消息并等待响应"""
        if not self.connected:
            print("❌ 未连接")
            return None
        
        msg_id = message["id"]
        future = asyncio.Future()
        self.pending_responses[msg_id] = future
        
        try:
            await self.websocket.send(json.dumps(message))
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            print(f"⏱️ 请求超时 ({timeout}s)")
            return None
        except Exception as e:
            print(f"❌ 请求错误: {e}")
            return None
        finally:
            self.pending_responses.pop(msg_id, None)
    
    async def list_sessions(self) -> list:
        """查询所有Session"""
        list_msg = {
            "type": "req",
            "id": self._generate_id(),
            "method": "sessions.list",
            "params": {}
        }
        
        response = await self._send_and_wait(list_msg, timeout=10.0)
        if response and response.get("ok"):
            sessions = response.get("payload", {}).get("sessions", [])
            print(f"\n📋 找到 {len(sessions)} 个Session:")
            for s in sessions:
                sid = s.get('sessionId', 'N/A')[:20]
                created = s.get('createdAt', 'Unknown')[:19]
                print(f"  - {sid}... (创建于 {created})")
            return sessions
        else:
            error = response.get("error", "未知错误") if response else "无响应"
            print(f"⚠️ 无法获取Session列表: {error}")
            return []
    
    def on_event(self, event_name: str, handler: Callable):
        """注册事件处理器"""
        self.event_handlers[event_name] = handler
    
    async def disconnect(self):
        """断开连接"""
        if self.receive_task:
            self.receive_task.cancel()
            try:
                await self.receive_task
            except asyncio.CancelledError:
                pass
        
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
        
        self.connected = False
        self.authenticated = False
        print("🔌 已断开连接")


# ==================== 使用示例 ====================

async def main():
    # 配置 - 根据实际情况修改
    OPENCLAW_URI = "ws://hgq-nas:28789"
    # 使用 gateway auth token（不是配对的设备token！）
    TOKEN = "41ead91add7770665bbeb8f8b67416e68a61bf7d8ba70d29"
    
    client = OpenClawWebSocketClient(uri=OPENCLAW_URI, token=TOKEN)
    
    try:
        # 1. 连接并认证
        if not await client.connect():
            print("\n💡 故障排除建议：")
            print("   1. 确认Token正确：检查 ~/.openclaw/config 或 Gateway日志")
            print("   2. 确认Gateway运行：openclaw gateway status")
            print("   3. 检查设备配对：在Gateway主机运行 'openclaw devices list'")
            print("   4. 查看Gateway日志：openclaw logs | grep -i websocket")
            return
        
        # 2. 查询现有Session
        await client.list_sessions()
        
        # 3. 创建新Session
        session_id = await client.create_session(description="Python WebSocket测试")
        if not session_id:
            print("无法创建Session，退出")
            return
        
        # 4. 交互式对话
        print("\n" + "="*50)
        print("对话开始（输入 'quit' 退出，'new' 创建新Session）")
        print("="*50)
        
        while True:
            try:
                user_input = input("\n👤 You: ").strip()
                
                if user_input.lower() == 'quit':
                    break
                elif user_input.lower() == 'new':
                    session_id = await client.create_session(description="新Session")
                    continue
                elif user_input.lower() == 'list':
                    await client.list_sessions()
                    continue
                elif not user_input:
                    continue
                
                # 发送消息
                await client.chat(user_input, stream=True)
                
            except EOFError:
                break
            except KeyboardInterrupt:
                break
        
        # 5. 结束
        print("\n📊 最终Session列表:")
        await client.list_sessions()
        
    finally:
        await client.disconnect()
        print("\n👋 再见！")


if __name__ == "__main__":
    asyncio.run(main())

