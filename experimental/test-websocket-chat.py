#!/usr/bin/env python3
"""
OpenClaw WebSocket 客户端

用法:
    python test-websocket-chat.py [--uri WS_URL] [--token TOKEN]

示例:
    python test-websocket-chat.py --uri ws://hgq-nas:28789 --token your-token
"""

import argparse
import asyncio
import json
import os
import socket
import sys
import uuid
import base64
import hashlib
import time
from datetime import datetime
from typing import Optional, Callable, Dict, Any, List

import websockets
from websockets.exceptions import ConnectionClosed
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# ============ 常量 ============

PROTOCOL_VERSION = 3
DEFAULT_SCOPES = ["operator.admin", "operator.approvals", "operator.pairing"]
ED25519_SPKI_PREFIX = bytes([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])

KEYPAIR_FILE = os.path.expanduser("~/.openclaw/python-client-identity.json")


# ============ 密钥管理 ============

def generate_keypair() -> Dict[str, str]:
    """生成 Ed25519 密钥对"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    # 计算 deviceId - 去除 SPKI prefix 后 SHA256
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_raw = public_der[len(ED25519_SPKI_PREFIX):]
    device_id = hashlib.sha256(public_raw).hexdigest()
    
    # base64url 格式公钥
    public_b64url = base64.urlsafe_b64encode(public_raw).decode().rstrip('=')
    
    return {
        "device_id": device_id,
        "private_key": private_pem,
        "public_key": public_b64url,
    }


def load_or_create_keypair() -> Dict[str, str]:
    """加载或创建密钥对"""
    if os.path.exists(KEYPAIR_FILE):
        with open(KEYPAIR_FILE, "r") as f:
            return json.load(f)
    
    keypair = generate_keypair()
    os.makedirs(os.path.dirname(KEYPAIR_FILE), exist_ok=True)
    with open(KEYPAIR_FILE, "w") as f:
        json.dump(keypair, f)
    os.chmod(KEYPAIR_FILE, 0o600)
    return keypair


# 初始化密钥
KEYPAIR = load_or_create_keypair()
DEVICE_ID = KEYPAIR["device_id"]
DEVICE_PRIVATE_KEY = KEYPAIR["private_key"]
DEVICE_PUBLIC_KEY = KEYPAIR["public_key"]


# ============ 签名函数 ============

def sign_payload(payload: str, private_key_pem: str) -> str:
    """使用 Ed25519 私钥签名"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    signature = private_key.sign(payload.encode())
    return base64.urlsafe_b64encode(signature).decode().rstrip('=')


def build_device_auth_payload(
    device_id: str,
    client_id: str,
    client_mode: str,
    role: str,
    scopes: List[str],
    signed_at_ms: int,
    nonce: str,
    token: str = ""
) -> str:
    """构建设备认证载荷 (v2 格式)"""
    return "|".join([
        "v2",
        device_id,
        client_id,
        client_mode,
        role,
        ",".join(scopes),
        str(signed_at_ms),
        token,
        nonce,
    ])


# ============ 客户端类 ============

class OpenClawWebSocketClient:
    def __init__(self, uri: str, token: str, origin: str = "http://localhost:18789"):
        self.uri = uri
        self.token = token
        self.origin = origin
        
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.connected = False
        self.authenticated = False
        self.session_id: Optional[str] = None
        self.device_token: Optional[str] = None
        
        self.message_counter = 0
        self.pending_responses: Dict[str, asyncio.Future] = {}
        self.event_handlers: Dict[str, Callable] = {}
        self.receive_task: Optional[asyncio.Task] = None
        
        self._challenge_nonce: Optional[str] = None
        self._hello_ok_received = False
        self._last_error: Optional[Dict] = None
    
    def _generate_id(self) -> str:
        self.message_counter += 1
        return f"msg-{self.message_counter}-{uuid.uuid4().hex[:8]}"
    
    async def connect(self) -> bool:
        """建立 WebSocket 连接并认证"""
        try:
            print(f"🔌 连接到 {self.uri}...")
            
            self.websocket = await websockets.connect(
                self.uri,
                ping_interval=20,
                ping_timeout=10,
                additional_headers={"Origin": self.origin}
            )
            self.connected = True
            print("✅ WebSocket 连接成功")
            
            # 启动接收循环
            self.receive_task = asyncio.create_task(self._receive_loop())
            
            # 等待获取 challenge nonce
            await asyncio.sleep(0.5)
            
            # 发送 connect 请求
            if not await self._send_connect():
                return False
            
            if self._hello_ok_received:
                self.authenticated = True
                print("✅ 认证成功")
                return True
            
            return False
                
        except Exception as e:
            print(f"❌ 连接错误: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def _send_connect(self) -> bool:
        """发送 connect 请求"""
        nonce = self._challenge_nonce or ""
        signed_at_ms = int(time.time() * 1000)
        
        # 签名载荷中使用 token
        payload = build_device_auth_payload(
            device_id=DEVICE_ID,
            client_id="cli",
            client_mode="cli",
            role="operator",
            scopes=DEFAULT_SCOPES,
            signed_at_ms=signed_at_ms,
            nonce=nonce,
            token=self.token
        )
        
        signature = sign_payload(payload, DEVICE_PRIVATE_KEY)
        
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
            "scopes": DEFAULT_SCOPES,
            "role": "operator",
            "auth": {"token": self.token},
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
        
        try:
            await self.websocket.send(json.dumps(connect_msg))
            await asyncio.sleep(2)
            
            if self._hello_ok_received:
                print("✅ 收到 hello-ok！")
                return True
            
            # 检查配对错误
            if self._last_error and self._last_error.get("code") in ["NOT_PAIRED", "PAIRING_REQUIRED"]:
                request_id = self._last_error.get("details", {}).get("requestId")
                if request_id:
                    print(f"🔗 需要配对设备！")
                    print(f"📋 请在 Gateway 上运行: openclaw devices approve {request_id}")
                    input("   按回车键继续（批准配对后）...")
                    await self.disconnect()
                    return await self.connect()
            
            return True
        except Exception as e:
            print(f"❌ Connect 错误: {e}")
            return False
    
    async def _receive_loop(self):
        """后台接收循环"""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message)
                    await self._handle_message(data)
                except json.JSONDecodeError:
                    pass
        except ConnectionClosed as e:
            print(f"🔌 连接已关闭 (code: {e.code})")
            self.connected = False
            self.authenticated = False
        except Exception as e:
            print(f"❌ 接收错误: {e}")
            self.connected = False
    
    async def _handle_message(self, data: Dict[str, Any]):
        """处理收到的消息"""
        msg_type = data.get("type")
        msg_id = data.get("id")
        
        # Challenge 事件
        if msg_type == "event" and data.get("event") == "connect.challenge":
            self._challenge_nonce = data.get("payload", {}).get("nonce")
            return
        
        # 错误响应
        if msg_type == "res" and data.get("ok") == False:
            error = data.get("error", {})
            self._last_error = error
            
            # 打印关键错误
            code = error.get("code", "")
            if code in ["NOT_PAIRED", "PAIRING_REQUIRED", "INVALID_REQUEST"]:
                print(f"❌ {error.get('message', code)}")
            
            if msg_id and msg_id in self.pending_responses:
                self.pending_responses[msg_id].set_result(data)
            return
        
        # Hello-ok 响应
        if msg_type == "res" and data.get("ok") == True:
            payload = data.get("payload", {})
            if payload.get("type") == "hello-ok":
                auth_info = payload.get("auth", {})
                self.device_token = auth_info.get("deviceToken")
                self._hello_ok_received = True
                
                if self.device_token:
                    print(f"✅ deviceToken: {self.device_token[:20]}...")
                    print(f"✅ scopes: {auth_info.get('scopes')}")
            
            if msg_id and msg_id in self.pending_responses:
                self.pending_responses[msg_id].set_result(data)
            return
        
        # 匹配 pending 请求
        if msg_id and msg_id in self.pending_responses:
            self.pending_responses[msg_id].set_result(data)
            return
        
        # 事件处理 - 支持 method 和 event 两种格式
        event_name = data.get("event") or data.get("method")
        if event_name:
            handler = self.event_handlers.get(event_name)
            if handler:
                # 事件消息的 payload 在 data 中
                payload = data.get("data", data.get("payload", data.get("params", {})))
                await handler(payload)
            elif event_name not in ["ping", "pong", "tick", "health"]:
                pass
    
    async def create_session(self, session_key: str = "agent:default:chat") -> Optional[str]:
        """创建新 Session"""
        self.session_id = session_key
        
        init_msg = {
            "type": "req",
            "id": self._generate_id(),
            "method": "chat.send",
            "params": {
                "sessionKey": self.session_id,
                "message": "Hello from Python WebSocket Client",
                "idempotencyKey": self._generate_id(),
            }
        }
        
        response = await self._send_and_wait(init_msg, timeout=30.0)
        if response and response.get("ok"):
            print(f"✅ Session 创建成功: {self.session_id}")
            return self.session_id
        
        error = response.get("error", {}) if response else {}
        print(f"❌ Session 创建失败: {error.get('message', '未知错误')}")
        return None
    
    async def chat(self, message: str) -> Optional[str]:
        """发送对话消息"""
        if not self.session_id:
            print("❌ 请先创建 Session")
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
        
        print("🤖 Assistant: ", end="", flush=True)
        
        # 收集流式输出
        full_content: List[str] = []
        response_done = asyncio.Event()
        
        async def handle_chat_event(params: Dict):
            nonlocal full_content
            state = params.get("state", "")
            msg = params.get("message", {})
            content = msg.get("content", [])
            for c in content:
                text = c.get("text", "")
                if text:
                    print(text, end="", flush=True)
                    full_content.append(text)
            
            if state == "final":
                response_done.set()
                print()
        
        self.event_handlers["chat"] = handle_chat_event
        
        try:
            await self.websocket.send(json.dumps(chat_msg))
            
            # 等待响应完成，最多等待30秒
            try:
                await asyncio.wait_for(response_done.wait(), timeout=30.0)
            except asyncio.TimeoutError:
                print(" (timeout)", end="")
            
            return "".join(full_content)
        except Exception as e:
            print(f"\n❌ 发送失败: {e}")
            return None
        finally:
            self.event_handlers.pop("chat", None)
    
    async def list_sessions(self) -> List[Dict]:
        """查询 Session 列表"""
        list_msg = {
            "type": "req",
            "id": self._generate_id(),
            "method": "sessions.list",
            "params": {}
        }
        
        response = await self._send_and_wait(list_msg, timeout=10.0)
        if response and response.get("ok"):
            sessions = response.get("payload", {}).get("sessions", [])
            print(f"\n📋 找到 {len(sessions)} 个 Session:")
            for s in sessions:
                sid = s.get('sessionId', 'N/A')[:24]
                created = s.get('createdAt', 'Unknown')[:19]
                print(f"  - {sid}")
            return sessions
        
        error = response.get("error", {}) if response else {}
        print(f"⚠️ 获取 Session 失败: {error.get('message', '未知错误')}")
        return []
    
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
            print(f"⏱️ 请求超时")
            return None
        except Exception as e:
            print(f"❌ 请求错误: {e}")
            return None
        finally:
            self.pending_responses.pop(msg_id, None)
    
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


# ============ 主程序 ============

async def main():
    parser = argparse.ArgumentParser(description="OpenClaw WebSocket 客户端")
    parser.add_argument("--host", default="localhost", help="Gateway 主机地址 (IP 或域名)")
    parser.add_argument("--port", type=int, default=28789, help="Gateway 端口")
    parser.add_argument("--token", default="", help="Gateway token")
    parser.add_argument("--ssl", action="store_true", help="使用 WSS (HTTPS)")
    parser.add_argument("--test", "-t", metavar="MSG", help="测试模式：发送消息后自动退出")
    args = parser.parse_args()
    
    # 构建 URI
    scheme = "wss" if args.ssl else "ws"
    uri = f"{scheme}://{args.host}:{args.port}"
    origin = f"http{'s' if args.ssl else ''}://{args.host}:{args.port}"
    
    # 如果没有传入 token，尝试从环境变量读取
    token = args.token or os.environ.get("OPENCLAW_TOKEN", "")
    if not token:
        print("❌ 请通过 --token 或 OPENCLAW_TOKEN 环境变量提供 token")
        sys.exit(1)
    
    print(f"📱 设备ID: {DEVICE_ID}")
    print(f"🔗 连接到 {uri}")
    
    client = OpenClawWebSocketClient(uri=uri, token=token, origin=origin)
    
    try:
        if not await client.connect():
            print("\n💡 故障排除:")
            print("   1. 确认 Token 正确")
            print("   2. 确认 Gateway 正在运行")
            print("   3. 检查设备配对状态")
            return
        
        await client.list_sessions()
        
        session_id = await client.create_session()
        if not session_id:
            print("无法创建 Session")
            return
        
        print("对话开始（输入 'quit' 退出，'new' 创建新 Session）")
        print(f"{'='*50}")
        
        # 测试模式：发送一条消息后自动退出
        if args.test:
            print(f"\n🧪 测试模式")
            print(f"👤 You: {args.test}")
            await client.chat(args.test)
            print("\n👋 测试完成")
        else:
            while True:
                try:
                    user_input = input("\n👤 You: ").strip()
                    
                    if user_input.lower() == "quit":
                        break
                    elif user_input.lower() == "new":
                        await client.create_session()
                        continue
                    elif user_input.lower() == "list":
                        await client.list_sessions()
                        continue
                    elif not user_input:
                        continue
                    
                    await client.chat(user_input)
                    
                except (EOFError, KeyboardInterrupt):
                    break
        
        print("\n👋 再见！")
        
    finally:
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
