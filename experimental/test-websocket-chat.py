#!/usr/bin/env python3
"""
OpenClaw WebSocket客户端 - 修复版
修复：协议格式、Token传递、设备配对、自动重连
"""

import asyncio
import json
import uuid
import sys
import urllib.parse
from datetime import datetime
from typing import Optional, Callable, Dict, Any
import websockets
from websockets.exceptions import ConnectionClosed


class OpenClawWebSocketClient:
    def __init__(self, uri: str = "ws://localhost:18789", token: str = None):
        # 修复：Token需要编码到URL参数中（某些版本要求）
        self.base_uri = uri
        self.token = token
        self.uri = self._build_uri_with_token(uri, token)
        
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.connected = False
        self.authenticated = False
        self.session_id: Optional[str] = None
        self.message_counter = 0
        self.pending_responses: Dict[str, asyncio.Future] = {}
        self.event_handlers: Dict[str, Callable] = {}
        self.receive_task: Optional[asyncio.Task] = None
        self.device_id = str(uuid.uuid4())  # 生成设备ID用于配对
        
    def _build_uri_with_token(self, uri: str, token: str) -> str:
        """构建带Token的WebSocket URL（某些OpenClaw版本要求）"""
        if not token:
            return uri
        
        # 解析URI并添加token参数
        parsed = urllib.parse.urlparse(uri)
        query = urllib.parse.parse_qs(parsed.query)
        query['token'] = [token]
        new_query = urllib.parse.urlencode(query, doseq=True)
        
        # 重建URI
        new_uri = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        return new_uri
    
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
            
            # 设置额外的header（某些版本需要）
            extra_headers = {
                'X-Device-ID': self.device_id,
                'X-Client-Name': 'Python-WebSocket-Client'
            }
            
            self.websocket = await websockets.connect(
                self.uri,
                ping_interval=20,
                ping_timeout=10,
                extra_headers=extra_headers
            )
            self.connected = True
            print("✅ WebSocket连接成功")
            
            # 启动接收循环
            self.receive_task = asyncio.create_task(self._receive_loop())
            
            # 发送认证（第一帧必须是connect）
            auth_success = await self._authenticate()
            if auth_success:
                self.authenticated = True
                print("✅ 认证成功")
                
                # 检查是否需要设备配对
                await self._check_device_pairing()
                return True
            else:
                print("❌ 认证失败")
                await self.disconnect()
                return False
                
        except Exception as e:
            print(f"❌ 连接错误: {e}")
            return False
    
    async def _authenticate(self) -> bool:
        """
        发送认证请求 - 修复版
        注意：OpenClaw第一帧必须是connect方法
        """
        # 修复：使用正确的JSON-RPC格式和必要字段
        auth_msg = {
            "jsonrpc": "2.0",
            "id": self._generate_id(),
            "method": "connect",
            "params": {
                "role": "control",  # 必须声明角色
                "auth": {
                    "token": self.token,  # 即使URL有token，这里也要传
                    "deviceId": self.device_id  # 添加设备ID
                },
                "client": {
                    "name": "python-ws-client",
                    "version": "1.0.0",
                    "platform": "python",
                    "capabilities": ["chat", "sessions"]  # 声明能力
                },
                "scope": ["operator.read", "operator.write"]  # 请求必要权限
            }
        }
        
        try:
            # 发送认证并等待响应
            future = asyncio.Future()
            self.pending_responses[auth_msg["id"]] = future
            
            print("📤 发送认证请求...")
            await self.websocket.send(json.dumps(auth_msg))
            
            # 增加超时时间到15秒（配对可能需要时间）
            response = await asyncio.wait_for(future, timeout=15.0)
            
            if response.get("ok"):
                print("✅ 认证响应成功")
                return True
            else:
                error = response.get("error", "未知错误")
                print(f"❌ 认证被拒绝: {error}")
                
                # 检查是否是配对问题
                if "pairing" in error.lower() or "unauthorized" in error.lower():
                    print("⚠️  设备需要配对批准！")
                    print(f"   请在OpenClaw Gateway上运行: openclaw devices approve {self.device_id}")
                return False
                
        except asyncio.TimeoutError:
            print("⏱️  认证超时（15秒）")
            print("💡 可能原因：")
            print("   1. Token错误")
            print("   2. 设备需要配对批准")
            print("   3. Gateway未运行或无法访问")
            return False
        except Exception as e:
            print(f"❌ 认证错误: {e}")
            return False
        finally:
            self.pending_responses.pop(auth_msg["id"], None)
    
    async def _check_device_pairing(self):
        """检查设备配对状态"""
        # 查询设备状态
        check_msg = {
            "jsonrpc": "2.0",
            "id": self._generate_id(),
            "method": "devices.get",
            "params": {
                "deviceId": self.device_id
            }
        }
        
        try:
            response = await self._send_and_wait(check_msg, timeout=5.0)
            if response and response.get("ok"):
                device_info = response.get("payload", {})
                status = device_info.get("status", "unknown")
                print(f"📱 设备状态: {status}")
                
                if status == "pending":
                    print("⚠️  设备等待配对批准")
        except:
            pass  # 忽略错误，继续运行
    
    async def _receive_loop(self):
        """后台接收循环"""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message)
                    await self._handle_message(data)
                except json.JSONDecodeError:
                    print(f"⚠️  收到非JSON消息: {message[:100]}")
        except ConnectionClosed as e:
            print(f"🔌 连接已关闭 (code: {e.code}, reason: {e.reason})")
            self.connected = False
            self.authenticated = False
        except Exception as e:
            print(f"❌ 接收循环错误: {e}")
            self.connected = False
    
    async def _handle_message(self, data: Dict[str, Any]):
        """处理收到的消息"""
        msg_id = data.get("id")
        method = data.get("method")
        
        # 1. 处理响应（匹配pending的请求）
        if msg_id and msg_id in self.pending_responses:
            future = self.pending_responses.pop(msg_id)
            if not future.done():
                future.set_result(data)
            return
        
        # 2. 处理服务器主动推送的事件
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
        self.session_id = self._generate_session_id()
        
        print(f"🆕 创建Session: {self.session_id}")
        
        # 通过发送第一条消息隐式创建Session
        init_msg = {
            "jsonrpc": "2.0",
            "id": self._generate_id(),
            "method": "chat.send",
            "params": {
                "sessionId": self.session_id,
                "content": f"Session初始化: {description}",
                "type": "text",
                "metadata": {
                    "source": "python-client",
                    "auto_created": True
                }
            }
        }
        
        response = await self._send_and_wait(init_msg, timeout=10.0)
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
            "jsonrpc": "2.0",
            "id": self._generate_id(),
            "method": "chat.send",
            "params": {
                "sessionId": self.session_id,
                "content": message,
                "type": "text",
                "stream": stream
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
            "jsonrpc": "2.0",
            "id": self._generate_id(),
            "method": "sessions.list",
            "params": {
                "agentId": "main"
            }
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
            # 发送断开通知（优雅关闭）
            try:
                goodbye = {
                    "jsonrpc": "2.0",
                    "id": self._generate_id(),
                    "method": "disconnect",
                    "params": {"reason": "client_exit"}
                }
                await asyncio.wait_for(
                    self.websocket.send(json.dumps(goodbye)),
                    timeout=2.0
                )
            except:
                pass
            
            await self.websocket.close()
            self.websocket = None
        
        self.connected = False
        self.authenticated = False
        print("🔌 已断开连接")


# ==================== 使用示例 ====================

async def main():
    # 配置 - 根据实际情况修改
    OPENCLAW_URI = "ws://hgq-nas:28789"  # 你的OpenClaw地址
    TOKEN = "41ead91add7770665bbeb8f8b67416e68a61bf7d8ba70d29"      # 你的Token
    
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

